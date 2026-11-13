"""Yerel test hedefi: 3 sanal host, sızdırılmış dosyalar ve sırlar içeren JS."""
import http.server, socketserver

ROOT_HTML = b"""<html><head><title>Recon Lab</title><script src="/static/app.js"></script>
<script src="/static/jquery.min.js"></script></head><body>
<a href="/index.php?id=1&cat=2">urun</a> <a href="/index.php?id=5&cat=9">urun2</a>
<a href="/search.php?q=test">ara</a> <a href="/about/">hakkinda</a>
<a href="https://api.recon-lab.test/v1/users?id=1">api</a></body></html>"""
APP_JS = b"""var cfg = {
  apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
  endpoint: "/api/v2/internal/users",
};
const AWS = "AKIAIOSFODNN7EXAMPLE";
var password = "changeme";
var adminPanel = "/admin/login";
let token = "s3cr3tTokenValue99";
"""
SITES = {
  "recon-lab.test": {
    "headers": {"X-Powered-By": "PHP/8.1.2", "Set-Cookie": "PHPSESSID=abc; path=/"},
    "files": {"/": ("text/html", ROOT_HTML), "/index.php": ("text/html", ROOT_HTML),
              "/about/": ("text/html", b"<html><title>About</title><a href='/contact.php?ref=about'>c</a></html>"),
              "/static/app.js": ("application/javascript", APP_JS),
              "/static/jquery.min.js": ("application/javascript", b"/*! jQuery */ var secret='x';"),
              "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
              "/.env": ("text/plain", b"APP_KEY=base64:xxx\nDB_PASSWORD=hunter2\n"),
              "/backup.zip": ("application/zip", b"PK\x03\x04" + b"\0" * 100),
              "/recon-lab.test.zip": ("application/zip", b"PK\x03\x04" + b"\0" * 50),
              "/phpinfo.php": ("text/html", b"<html>PHP Version 8.1.2</html>"),
              "/robots.txt": ("text/plain", b"User-agent: *\nDisallow: /secret-area/\n"),
              "/secret-area/": ("text/html", b"<html>secret</html>")},
    "wildcard": False},
  "app.recon-lab.test": {
    "headers": {"X-Powered-By": "Express"},
    "files": {"/": ("text/html", b"<html><title>App</title><script src='/static/main.js'></script></html>"),
              "/static/main.js": ("application/javascript",
                   b"fetch('/api/orders?user=1');\nconst k='AKIAABCDEFGHIJKLMNOP';\nconst gh='ghp_" + b"a"*36 + b"';"),
              "/package.json": ("application/json", b'{"name":"app","dependencies":{"express":"4"}}')},
    "wildcard": True},   # her yola 200 (soft-404)
  "api.recon-lab.test": {
    "headers": {"Set-Cookie": "JSESSIONID=1; Path=/", "Server": "Apache-Coyote/1.1"},
    "files": {"/": ("text/html", b"<html><title>API</title></html>"),
              "/v1/users": ("application/json", b'{"users":[]}'),
              "/actuator/env": ("application/json", b'{"activeProfiles":["prod"],"propertySources":[]}'),
              "/manager/html": ("text/html", b"401")},
    "wildcard": False},
}
hits = {"n": 0}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        hits["n"] += 1
        host = (self.headers.get("Host") or "").split(":")[0]
        site = SITES.get(host)
        if not site:
            self.send_response(404); self.end_headers(); return
        path = self.path.split("?")[0]
        if path == "/manager/html" and host.startswith("api"):
            self.send_response(401); self.send_header("WWW-Authenticate", "Basic"); self.end_headers(); return
        if path in site["files"]:
            ctype, body = site["files"][path]; code = 200
        elif path + "/" in site["files"]:
            self.send_response(301); self.send_header("Location", path + "/"); self.end_headers(); return
        elif site["wildcard"]:
            ctype, body, code = "text/html", b"<html><title>App</title>Sayfa bulunamadi ama 200</html>", 200
        else:
            ctype, body, code = "text/html", b"<html>404 Not Found</html>", 404
        self.send_response(code)
        for k, v in site["headers"].items(): self.send_header(k, v)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True

S(("0.0.0.0", 80), H).serve_forever()
