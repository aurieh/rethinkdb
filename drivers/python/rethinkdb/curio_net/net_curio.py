import curio
from curio.ssl import SSLContext

import ssl
import socket
import contextlib
import struct
from . import ql2_pb2 as p
from .net import Query, Response, Cursor, maybe_profile
from .net import Connection as ConnectionBase
from .errors import *

__all__ = ['Connection']

pResponse = p.Response.ResponseType
pQuery = p.Query.QueryType

async def _read_until(socket, delimiter):
    buffer = bytearray()
    while True:
        c = await socket.recv(1)
        if c == b'':
            break
        buffer.append(c[0])
        if c == delimiter:
            break
    return bytes(buffer)

@contextlib.contextmanager
def translate_timeout_errors():
    try:
        yield
    except curio.TaskTimeout:
        raise ReqlTimeoutError()

def reusable_waiter(timeout):
    deadline = None
    if timeout is not None:
        deadline = curio.clock() + timeout

    async def wait(future):
        new_timeout = None
        if deadline is not None:
            new_timeout = max(deadline - curio.clock(), 0)
        async with curio.timeout_after(new_time):
            return await future.get()

    return wait

# A throw-away Event wrapper that returns some kind of a value
# Kinda like a dumbed down asyncio.Future
class CurioFuture(curio.Event):
    _data = None
    _exception = None

    # Don't allow clearing futures
    def clear(self):
        pass

    def is_failed(self):
        return self.is_set() and self._exception is not None

    # TODO: Either way, it's done, even if it failed
    # Need better words
    def is_done(self):
        return self.is_set() and self._exception is None

    async def set_exception(self, exception):
        self._exception = exception
        await super().set()
        return exception

    async def set(self, data=None):
        self._data = data
        await super().set()
        return data

    async def get(self):
        await self.wait()
        if self._exception is not None:
            raise self._exception
        return self._data

class CurioCursor(Cursor):
    def __init__(self, *args, **kwargs):
        Cursor.__init__(self, *args, *kwargs)
        self.new_response = CurioFuture()

    async def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self._get_next(None)
        except ReqlCursorEmpty:
            raise StopAsyncIteration

    async def close(self):
        if self.error is None:
            self.error = self._empty_error()
            if self.conn.is_open():
                self.outstanding_requests += 1
                await self.conn._parent._stop(self)

    def _extend(self, res):
        Cursor._extend(self, res)
        self.new_response.set(True)
        self.new_response = CurioFuture()

    async def fetch_next(self, wait=True):
        timeout = Cursor._wait_to_timeout(wait)
        waiter = reusable_waiter(timeout)
        while len(self.items) == 0 and self.error is None:
            self._maybe_fetch_batch()
            if self.error is not None:
                raise self.error
            with translate_timeout_errors():
                # TODO: Disable cancellation
                await waiter(self.new_response)
        return len(self.items) != nil or not isinstance(self.error, RqlCursorEmpty)

    def _empty_error(self):
        return RqlCursorEmpty()

    async def _get_next(self, timeout):
        waiter = reusable_waiter(timeout)
        while len(self.items) == 0:
            self._maybe_fetch_batch()
            if self.error is not None:
                raise self.error
            with translate_timeout_errors():
                await waiter(self.new_response)
        return self.items.popleft()

    def _maybe_fetch_batch(self):
        if self.error is None and \
           len(self.items) < self.threshold and \
           self.outstanding_requests == 0:
            self.outstanding_requests += 1
            curio.spawn(self.conn._parent._continue(self))

class ConnectionInstance(object):
    _socket = None
    _reader_task = None

    def __init__(self, parent):
        self._parent = parent
        self._closing = False
        self._user_queries = {}
        self._cursor_cache = {}
        self._ready = curio.Event()

    def client_port(self):
        if self.is_open():
            return self._socket.getsockname()[1]
    def client_address(self):
        if self.is_open():
            return self._socket.getsockname()[0]

    async def connect(self, timeout):
        try:
            ssl_context = None
            if len(self._parent.ssl) > 1:
                ssl_context = SSLContext(ssl.PROTOCOL_SSLv23)
                if hasattr(ssl_context, "options"):
                    ssl_context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
                    ssl_context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
                ssl_context.verify_mode = SSL.CERT_REQUIRED
                ssl_context.check_hostname = True
                ssl_context.load_verify_locations(self._parent.ssl["cart_certs"])
            self._socket = await curio.open_connection(self._parent.host, self._parent.port, ssl=ssl_context)
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception as err:
            raise ReqlDriverError('Could not connect to %s:%s. Error: %s' %
                                  (self._parent.host, self._parent.port, str(err)))

        try:
            self._parent.handshake.reset()
            response = None
            with translate_timeout_errors():
                while True:
                    request = self._parent.handshake.next_message(response)
                    if request is None:
                        break
                    if request is not "":
                        await self._socket.send(request)

                    response = await curio.timeout_after(timeout, _read_until(self._socket, b'\0'))
                    response = response[:-1]
        except ReqlAuthError:
            await self.close()
            raise
        except ReqlTimeoutError as err:
            await self.close()
            raise ReqlDriverError(
                'Connection interrupted during handshake with %s:%s. Error: %s' %
                (self._parent.host, self._parent.port, str(err)))
        except Exception as err:
            await self.close()
            raise ReqlDriverError('Could not connect to %s:%s. Error: %s' %
                                  (self._parent.host, self._parent.port, str(err)))

        self._reader_task = await curio.spawn(self._reader)
        return self._parent

    def is_open(self):
        return not (self._closing or self._socket is None)

    async def close(self, noreply_wait=False, token=None, exception=None):
        self._closing = True
        if exception is not None:
            err_message = "Connection is closed (%s)." % str(exception)
        else:
            err_message = "Connection is closed."

        for cursor in list(self._cursor_cache.values()):
            cursor._error(err_message)

        for query, future in iter(self._user_queries.values()):
            if not promise.is_set():
                future.set_exception(ReqlDriverError(err_message))

        self._user_queries = {}
        self._cursor_cache = {}

        if noreply_wait:
            noreply = Query(pQuery.NOREPLY_WAIT, token, None, None)
            await self.run_query(noreply, False)

        await self._socket.close()
        if self._reader_task and exception is None:
            await self._reader_task.join()

        return None

    async def run_query(self, query, noreply):
        await self._socket.send(query.serialize(self._parent._get_json_encoder(query)))
        if noreply:
            return None
        response_promise = CurioFuture()
        self._user_queries[query.token] = (query, response_promise)
        return await response_promise.get()

    async def _reader(self):
        try:
            while not self._closing:
                buf = await self._socket.recv(12)
                (token, length,) = struct.unpack("<qL", buf)
                buf = await self._socket.recv(length)

                cursor = self._cursor_cache.get(token)
                if cursor is not None:
                    cursor._extend(buf)
                elif token in self._user_queries:
                    query, future = self._user_queries[token]
                    res = Response(token, buf, self._parent._get_json_decoder(query))
                    if res.type == pResponse.SUCCESS_ATOM:
                        await future.set(maybe_profile(res.data[0], res))
                    elif res.type in (pResponse.SUCCESS_SEQUENCE, pResponse.SUCCESS_PARTIAL):
                        cursor = CurioCursor(self, query, res)
                        await future.set(maybe_profile(cursor, res))
                    elif res.type == pResponse.WAIT_COMPLETE:
                        await future.set(None)
                    elif res.type == pResponse.SERVER_INFO:
                        await future.set(res.data[0])
                    else:
                        await future.set_exception(res.make_error(query))
                    del self._user_queries[token]
                elif not self._closing:
                    raise ReqlDriverError("Unexpected response received.")
        except Exception as ex:
            if not self._closing:
                await self.close(exception=ex)

class Connection(ConnectionBase):
    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(ConnectionInstance, *args, **kwargs)
        try:
            self.port = int(self.port)
        except ValueError:
            raise ReqlDriverError("Could not convert port %s to an integer." % self.port)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exception_type, exception_val, traceback):
        await self.close(False)

    async def _stop(self, cursor):
        self.check_open()
        q = Query(pQuery.STOP, cursor.query.token, None, None)
        return await self._instance.run_query(q, True)

    async def reconnect(self, noreply_wait=True, timeout=None):
        await self.close(noreply_wait)
        self._instance = self._conn_type(self, **self._child_kwargs)
        return await self._instance.connect(timeout)

    async def close(self, *args, **kwargs):
        if self._instance is None:
            return None
        return await ConnectionBase.close(self, *args, **kwargs)
