"""Key proxy for one OpenCode run (nc-work opencode). Runs as its own container in the task's network; OpenCode talks
to it with the placeholder key nc-keyproxy, this adds the real OpenRouter key and forwards to https://openrouter.ai
through the task's egress proxy. No agent container ever holds the key.

The key comes on stdin (one line, then stdin is closed), never from the environment or argv, so it is in neither the
container's configuration nor `docker inspect` nor the environment of a `docker exec`. It is never logged and never
written into an answer. Only the method/path pairs OpenCode needs pass (OpenCode 2.2.7, measured
before this proxy was written, calls POST /api/v1/chat/completions for answers and titles, nothing else); the raw request target is compared byte
for byte, and upstream always gets the constant path from the list. Standard library only, mounted read-only.
"""
import http.client, re, socket, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Header limits for this process (requests and upstream answers): at most 64 lines of 16 KiB, instead of 100 of 64 KiB,
# so 32 connections cannot fill the container's 256 MiB. Too many or too long: 431 from parse_request.
http.client._MAXHEADERS, http.client._MAXLINE = 64, 16 * 1024

ROUTES = {(b'POST', b'/api/v1/chat/completions'): '/api/v1/chat/completions'}
READY = (b'GET', b'/__ready')
METHODS = {b'GET', b'POST'}                  # anything else (CONNECT, OPTIONS, …) is 405, unknown paths 404
FORWARD = ('Content-Type', 'Accept', 'HTTP-Referer', 'X-Title')  # from the client; everything else is dropped
RETURN = ('Content-Type', 'Cache-Control', 'Retry-After')        # from upstream back to the client
BODY_MAX = 8 * 1024 * 1024
SLOTS, CONNECTIONS = 8, 32
UPSTREAM, EGRESS = ('openrouter.ai', 443), ('egress', 3128)
REASONS = {400: 'Bad Request', 404: 'Not Found', 405: 'Method Not Allowed', 411: 'Length Required',
           413: 'Payload Too Large', 502: 'Bad Gateway', 503: 'Service Unavailable'}

def norm(name):
    """A header name as the proxy compares it: any spelling of Transfer-Encoding or Content-Length is caught."""
    return re.sub(r'[\s_]+', '-', name.strip().lower())

def serve(key, port=8080, host='0.0.0.0', upstream=UPSTREAM, tls=True, tunnel=True, egress=EGRESS,
          read_timeout=60, idle_timeout=600, log=None):
    """The server, not yet serving. In the container the target is fixed (openrouter.ai:443 over TLS, tunnelled through
    egress:3128 with a verified certificate); tests point it at a local plain HTTP server."""
    log = log or sys.stdout
    slots = threading.BoundedSemaphore(SLOTS)
    # Request line and headers within read_timeout from the accept, however slowly they trickle in: one watchdog
    # thread (not one per connection: threads count against the pids limit) shuts down sockets past their deadline.
    deadlines, guard = {}, threading.Lock()
    def watchdog():
        while True:
            time.sleep(min(1.0, read_timeout / 4))
            now = time.monotonic()
            with guard: late = [sock for sock, until in deadlines.items() if now > until]
            for sock in late:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
    threading.Thread(target=watchdog, daemon=True).start()
    context = ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt') if tls else None

    def say(what, status, size):
        try: print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), what, status, size, file=log, flush=True)
        except (OSError, ValueError): pass

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        timeout = read_timeout

        def log_message(self, *args): pass  # the base class would log the client's request line

        def reply(self, status, what='refused'):
            body = f'{status} {REASONS.get(status, "")}\n'.encode()
            try:
                self.send_response_only(status, REASONS.get(status))
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers(); self.wfile.write(body)
            except OSError: pass
            say(what, status, len(body))

        def handle_one_request(self):
            self.close_connection = True
            with guard: deadlines[self.connection] = time.monotonic() + read_timeout
            try:
                try:
                    self.raw_requestline = self.rfile.readline(8193)
                    if not self.raw_requestline or len(self.raw_requestline) > 8192: return
                    if not self.parse_request(): return  # 400 for a malformed line, 431 for too many or too long headers
                finally:
                    with guard: deadlines.pop(self.connection, None)  # the body has a deadline of its own
                parts = self.raw_requestline.rstrip(b'\r\n').split(b' ')
                if len(parts) != 3: return self.reply(400)
                method, target = parts[0], parts[1]
                if (method, target) == READY: return self.ready()
                if method not in METHODS: return self.reply(405)
                path = ROUTES.get((method, target))
                if path is None: return self.reply(404)
                if not slots.acquire(blocking=False): return self.reply(503)
                try: self.forward(method.decode(), path)
                finally: slots.release()
            except (OSError, ValueError): pass  # timeouts and dropped clients: the connection just ends

        def ready(self):
            body = b'ok\n'
            self.send_response_only(200, 'OK')
            self.send_header('Content-Length', str(len(body))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(body)

        def body(self):
            """The request body within read_timeout from now (whatever the client trickles), or an error status."""
            # A line the header parser cannot read (`Transfer-Encoding : x`) ends the headers there; never guess past it.
            if self.headers.defects or self.headers.get_payload(): return 400
            names = [norm(k) for k in self.headers.keys()]
            if 'transfer-encoding' in names: return 400
            lengths = [v for k, v in self.headers.items() if norm(k) == 'content-length']
            if not lengths: return 411
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0].strip()): return 400
            size = int(lengths[0].strip())
            if size > BODY_MAX: return 413
            deadline, data = time.monotonic() + read_timeout, bytearray()
            while len(data) < size:
                left = deadline - time.monotonic()
                if left <= 0: raise TimeoutError('body')
                self.connection.settimeout(left)
                chunk = self.rfile.read1(min(65536, size - len(data)))
                if not chunk: raise ConnectionError('body')
                data += chunk
            self.connection.settimeout(read_timeout)
            return bytes(data)

        def forward(self, method, path):
            what = f'{method} {path}'
            data = self.body()
            if isinstance(data, int): return self.reply(data)
            headers = [(name, self.headers.get(name)) for name in FORWARD if self.headers.get(name) is not None]
            if any(re.search(r'[\r\n\0]', v) for _, v in headers): return self.reply(400)
            try:
                if tunnel:
                    conn = (http.client.HTTPSConnection(*egress, timeout=idle_timeout, context=context) if tls
                            else http.client.HTTPConnection(*egress, timeout=idle_timeout))
                    conn.set_tunnel(*upstream)
                else:
                    conn = (http.client.HTTPSConnection(*upstream, timeout=idle_timeout, context=context) if tls
                            else http.client.HTTPConnection(*upstream, timeout=idle_timeout))
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                conn.putheader('Host', UPSTREAM[0])
                conn.putheader('Authorization', 'Bearer ' + key)
                for name, value in headers: conn.putheader(name, value)
                conn.putheader('Content-Length', str(len(data)))
                conn.putheader('Connection', 'close')
                conn.endheaders(data)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException, ValueError):
                return self.reply(502, what)
            sent = 0
            try:
                # 3xx is returned as it is, never followed, and without Location.
                self.send_response_only(resp.status, resp.reason)
                for name in RETURN:
                    if (value := resp.getheader(name)) is not None: self.send_header(name, value)
                self.send_header('Connection', 'close')
                self.end_headers()
                while chunk := resp.read1(65536):  # streamed: each piece goes out as it comes
                    self.wfile.write(chunk); sent += len(chunk)
            except (OSError, http.client.HTTPException): pass
            finally:
                conn.close()
                say(what, resp.status, sent)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True
        connections = threading.BoundedSemaphore(CONNECTIONS)
        def process_request(self, request, client_address):
            if not self.connections.acquire(blocking=False):  # threads count against the container's pids limit
                self.shutdown_request(request); return
            super().process_request(request, client_address)
        def process_request_thread(self, request, client_address):
            try: super().process_request_thread(request, client_address)
            finally: self.connections.release()
        def handle_error(self, request, client_address): pass  # never a traceback with request data

    server = Server((host, port), Handler)
    server.slots = slots  # for tests
    return server

def main():
    key = sys.stdin.readline().strip()
    sys.stdin.close()
    if not re.fullmatch(r'[\x21-\x7e]+', key):
        print('nc-keyproxy: no valid key on stdin', file=sys.stderr); sys.exit(2)
    serve(key).serve_forever()

if __name__ == '__main__':
    main()
