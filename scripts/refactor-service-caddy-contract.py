"""Exercise the real pinned Caddy binary; never stands in for Rust tests."""
import argparse
import datetime as dt
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    # A failed rerun must never leave an older success receipt at this path.
    output.mkdir(parents=True, exist_ok=False)
    caddy = Path(args.caddy).resolve()
    binary_sha = hashlib.sha256(caddy.read_bytes()).hexdigest()
    expected_sha = {
        "nt": "5f93a9bd555f3aac9d33af2756ba14b3519d8cca4ffd55256bdaeab444c9db2a",
        "posix": "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9",
    }.get(os.name)
    if binary_sha != expected_sha:
        raise RuntimeError("Caddy must be the verified v2.11.7 amd64 upstream binary for Windows or Linux")
    admin_port, http_port, https_port = (free_port() for _ in range(3))
    node = str(uuid.uuid4())
    hostname = "app.svc.example.test"
    origin = f"http://127.0.0.1:{admin_port}"
    prefix = f"nestlink-services-http-{node}"
    route_id = f"nestlink-pub-{node}-{uuid.uuid4()}"
    token = uuid.uuid4().hex
    seen = []
    streamed = threading.Event()
    response_started = threading.Event()
    response_continue = threading.Event()

    class Backend(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a):
            pass
        def do_GET(self):
            seen.append((self.headers, b""))
            if self.headers.get("Upgrade", "").lower() == "websocket":
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.end_headers()
                while raw := self.rfile.read(4):
                    self.wfile.write(raw)
                    self.wfile.flush()
                return
            if self.path == "/stream":
                self.send_response(200)
                self.send_header("Content-Length", "8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"part")
                self.wfile.flush()
                response_started.set()
                assert response_continue.wait(5), "streamed response fixture was not released"
                self.wfile.write(b"done")
                self.wfile.flush()
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")
        def do_POST(self):
            # The first bytes must arrive while the public writer is still open.
            first = self.rfile.read(4)
            streamed.set()
            rest = self.rfile.read(int(self.headers["Content-Length"]) - 4)
            seen.append((self.headers, first + rest))
            time.sleep(0.03)
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"late")
            self.wfile.flush()

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = output / "fixture-cert.pem", output / "fixture-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    def root(scheme):
        return {"@id":f"nestlink-services-{scheme}-{node}","handle":[{"handler":"subroute","routes":[]}]}
    config = {
        "admin":{"listen":f"127.0.0.1:{admin_port}","enforce_origin":True,"origins":[origin],"config":{"persist":False}},
        "apps":{"http":{"servers":{
            "http":{"listen":[f"127.0.0.1:{http_port}"],"automatic_https":{"disable":True},"read_header_timeout":"2s","idle_timeout":"30s","max_header_bytes":32768,"routes":[root("http")]},
            "https":{"listen":[f"127.0.0.1:{https_port}"],"strict_sni_host":True,"read_header_timeout":"2s","idle_timeout":"30s","max_header_bytes":32768,"tls_connection_policies":[{}],"automatic_https":{"disable":True},"routes":[root("https")]}
        }},"tls":{"certificates":{"load_files":[{"certificate":str(cert_file),"key":str(key_file)}]}}}
    }
    config_file = output / "caddy-fixture.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    validate = subprocess.run([str(caddy),"validate","--config",str(config_file)],capture_output=True,text=True,timeout=15)
    if validate.returncode:
        raise RuntimeError("actual Caddy rejected fixture config: " + validate.stderr[-3000:])
    log = (output / "caddy.log").open("wb")
    process = subprocess.Popen([str(caddy),"run","--config",str(config_file)],stdout=log,stderr=log,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def admin(method,path,value=None):
        request = urllib.request.Request(origin+path,data=None if value is None else json.dumps(value).encode(),headers={"Origin":origin,"Content-Type":"application/json"},method=method)
        try:
            with opener.open(request,timeout=3) as response:
                body = response.read()
                return response.status, None if not body else json.loads(body)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()
    def route(scheme, enabled):
        proxy = {"handler":"reverse_proxy","upstreams":[{"dial":f"127.0.0.1:{backend.server_port}"}],
                 "transport":{"protocol":"http","versions":["1.1"],"keep_alive":{"enabled":False}},
                 "headers":{"request":{"set":{"X-NestLink-Token":[token],"X-NestLink-Peer":["{http.request.remote}"],"X-NestLink-Scheme":["{http.request.scheme}"],"X-NestLink-SNI":["{http.request.tls.server_name}"]}}},"flush_interval":-1,"stream_close_delay":"1h"}
        return {"@id":route_id+scheme,"match":[{"host":[hostname]}],"terminal":True,"handle":[{"handler":"subroute","routes":[
            {"match":[{"path":["/.well-known/nestlink-ready/test"]}],"handle":[{"handler":"static_response","status_code":200,"body":"probe-ok"}],"terminal":True},
            {"handle":[proxy if enabled else {"handler":"static_response","status_code":503}],"terminal":True}]}]}
    checks = []
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if admin("GET", f"/id/{prefix}")[0] == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("actual Caddy admin did not start")
        missing_status = admin("GET", "/id/definitely-missing")[0]
        checks.append({"missing_id_status":missing_status})
        for scheme in ("http", "https"):
            status, body = admin("POST", f"/id/nestlink-services-{scheme}-{node}/handle/0/routes", route(scheme, False))
            assert status == 200, (status, body)
            assert admin("GET", f"/id/{route_id}{scheme}")[0] == 200
            # PATCH replaces an existing array element; PUT inserts before it.
            status, body = admin("PATCH", f"/id/{route_id}{scheme}", route(scheme, True))
            assert status == 200, (status, body)
        checks.append("exact-ID POST/PATCH/GET")
        context = ssl.create_default_context(cafile=str(cert_file))
        with socket.create_connection(("127.0.0.1",https_port),timeout=4) as raw:
            with context.wrap_socket(raw,server_hostname=hostname) as tls:
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nX-NestLink-Token: forged\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while chunk := tls.recv(65536):
                    data += chunk
                assert b"200 OK" in data and data.endswith(b"ok"), data
        assert seen[-1][0]["X-NestLink-Token"] == token
        assert seen[-1][0]["X-NestLink-SNI"] == hostname
        assert seen[-1][0]["X-NestLink-Scheme"] == "https"
        assert int(seen[-1][0]["X-NestLink-Peer"].rsplit(":",1)[1]) != 0
        checks.append("verified TLS/SNI and replaced private hop headers")
        with socket.create_connection(("127.0.0.1",https_port),timeout=4) as raw:
            with context.wrap_socket(raw,server_hostname=hostname) as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: attacker.example.test\r\nConnection: close\r\n\r\n")
                assert b"421" in tls.recv(4096)
        checks.append("strict Host/SNI mismatch rejection")
        with socket.create_connection(("127.0.0.1",http_port),timeout=4) as public:
            public.sendall(f"POST /upload HTTP/1.1\r\nHost: {hostname}\r\nContent-Length: 8\r\nConnection: close\r\n\r\npart".encode())
            assert streamed.wait(2), "Caddy buffered streaming upload"
            public.sendall(b"done")
            data = b""
            while chunk := public.recv(65536):
                data += chunk
            assert b"200 OK" in data and data.endswith(b"late"), data
        assert seen[-1][1] == b"partdone"
        assert seen[-1][0]["X-NestLink-SNI"] == ""
        checks.append("streamed upload and delayed response after complete HTTP request")
        with socket.create_connection(("127.0.0.1",http_port),timeout=4) as public:
            public.sendall(f"GET /ws HTTP/1.1\r\nHost: {hostname}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
            data = b""
            while b"\r\n\r\n" not in data:
                data += public.recv(4096)
            assert b"101" in data
            public.sendall(b"echo")
            assert public.recv(4) == b"echo"
            unrelated_id = f"nestlink-pub-{node}-{uuid.uuid4()}"
            unrelated = {"@id":unrelated_id,"match":[{"host":["unrelated.svc.example.test"]}],"handle":[{"handler":"static_response","status_code":503}],"terminal":True}
            changes = (("POST", f"/id/{prefix}/handle/0/routes", unrelated),
                       ("PATCH", f"/id/{unrelated_id}", unrelated),
                       ("DELETE", f"/id/{unrelated_id}", None))
            for index, (method, path, value) in enumerate(changes):
                assert admin(method, path, value)[0] == 200
                time.sleep(0.15)
                payload = f"ec{index:02}".encode()
                public.sendall(payload)
                assert public.recv(4) == payload, "unrelated route reload closed the established WebSocket"
        checks.append("WebSocket bidirectional upgrade retained across unrelated POST/PATCH/DELETE reloads")
        with socket.create_connection(("127.0.0.1",http_port),timeout=4) as public:
            public.sendall(f"GET /stream HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
            assert response_started.wait(2)
            data = b""
            while b"\r\n\r\n" not in data or not data.endswith(b"part"):
                chunk = public.recv(4096)
                assert chunk, "streamed response ended before route mutation"
                data += chunk
            assert admin("POST", f"/id/{prefix}/handle/0/routes", unrelated)[0] == 200
            response_continue.set()
            while chunk := public.recv(4096):
                data += chunk
            assert b"200 OK" in data and data.endswith(b"partdone"), data
            assert admin("DELETE", f"/id/{unrelated_id}")[0] == 200
        checks.append("existing streamed HTTP response retained across unrelated route reload")
        for scheme in ("http", "https"):
            assert admin("DELETE", f"/id/{route_id}{scheme}")[0] == 200
            assert admin("GET", f"/id/{route_id}{scheme}")[0] == missing_status
        checks.append("DELETE then confirmed absence")
        receipt = {"schema_version":1,"caddy_sha256":binary_sha,"version":subprocess.check_output([str(caddy),"version"],text=True).strip(),"checks":checks,"rust_compilation_run":False,"public_acme_run":False}
        (output / "http-contract-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=5)
        # Ephemeral fixture keys are unnecessary once the process has stopped.
        key_file.unlink(missing_ok=True)
    automatic = output / f"automatic-certificates-{uuid.uuid4()}"
    automatic_certificate_contract(automatic, caddy)
    automatic_receipt = automatic / "receipt.json"
    receipt.update(
        all_checks_passed=True,
        checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        automatic_certificate_receipt=str(automatic_receipt.relative_to(output)),
        automatic_certificate_receipt_sha256=hashlib.sha256(automatic_receipt.read_bytes()).hexdigest(),
    )
    (output / "receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(receipt,indent=2))

def automatic_certificate_contract(output, caddy):
    """Prove nested dynamic Host routes trigger real Caddy certificate workers.

    This fixture uses a local CA and explicitly disables OS trust installation.
    The production adapter always requires normal system-trusted certificates.
    """
    output.mkdir(parents=True, exist_ok=True)
    admin_port, http_port, https_port = (free_port() for _ in range(3))
    origin = f"http://127.0.0.1:{admin_port}"
    node = str(uuid.uuid4())
    hostname = "dynamic.svc.example.test"
    http_hostname = "clear.svc.example.test"
    def root(scheme):
        return {"@id":f"nestlink-services-{scheme}-{node}","handle":[{"handler":"subroute","routes":[]}]}
    config = {"admin":{"listen":f"127.0.0.1:{admin_port}","enforce_origin":True,"origins":[origin],"config":{"persist":False}},
              "apps":{"http":{"http_port":http_port,"https_port":https_port,"servers":{
                  "https":{"listen":[f"127.0.0.1:{https_port}"],"strict_sni_host":True,"tls_connection_policies":[{}],"automatic_https":{"disable_redirects":True},"routes":[root("https"),{"match":[{"host":["control.example.test"]}],"handle":[{"handler":"static_response","status_code":404}]}]},
                  "http":{"listen":[f"127.0.0.1:{http_port}"],"automatic_https":{"disable":True},"routes":[root("http")]}
              }},"tls":{"certificates":{"@id":f"nestlink-service-certificates-{node}","automate":[]},"automation":{"policies":[{"issuers":[{"module":"internal","ca":"local"}]}]}},
              "pki":{"certificate_authorities":{"local":{"install_trust":False}}}}}
    config_file = output / "caddy-automatic-fixture.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    environment = os.environ.copy()
    environment.update(APPDATA=str(output), XDG_DATA_HOME=str(output / "data"), XDG_CONFIG_HOME=str(output / "config"))
    log = (output / "caddy.log").open("wb")
    process = subprocess.Popen([str(caddy),"run","--config",str(config_file)],stdout=log,stderr=log,env=environment,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def admin(method, path, value=None):
        request = urllib.request.Request(origin+path,data=None if value is None else json.dumps(value).encode(),headers={"Origin":origin,"Content-Type":"application/json"},method=method)
        with opener.open(request,timeout=3) as response:
            body = response.read()
            return None if not body else json.loads(body)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                admin("GET", f"/id/nestlink-services-https-{node}")
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("automatic-certificate Caddy fixture did not start")
        ids = []
        for scheme, host in (("https", hostname),):
            route_id = f"nestlink-pub-{node}-{uuid.uuid4()}"
            ids.append(route_id)
            route = {"@id":route_id,"match":[{"host":[host]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"static_response","status_code":200,"body":"dynamic-ready"}],"terminal":True}]}],"terminal":True}
            admin("POST", f"/id/nestlink-services-{scheme}-{node}/handle/0/routes",route)
            if scheme == "https":
                admin("PATCH", f"/id/nestlink-service-certificates-{node}/automate", [host])
        deadline = time.monotonic() + 15
        last_error = None
        while time.monotonic() < deadline:
            try:
                roots = list(output.rglob("root.crt"))
                if not roots:
                    raise RuntimeError("local CA root not written yet")
                context = ssl.create_default_context(cafile=str(roots[0]))
                with socket.create_connection(("127.0.0.1",https_port),timeout=2) as raw:
                    with context.wrap_socket(raw,server_hostname=hostname) as tls:
                        assert ("DNS", hostname) in tls.getpeercert()["subjectAltName"]
                        tls.sendall(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                        body = b""
                        while chunk := tls.recv(4096):
                            body += chunk
                        assert b"200 OK" in body and body.endswith(b"dynamic-ready")
                break
            except (OSError, RuntimeError, AssertionError) as error:
                last_error = error
                time.sleep(0.1)
        else:
            raise RuntimeError("dynamic Host route did not acquire certificate") from last_error
        http_route_id = f"nestlink-pub-{node}-{uuid.uuid4()}"
        ids.append(http_route_id)
        admin("POST",f"/id/nestlink-services-http-{node}/handle/0/routes",{"@id":http_route_id,"match":[{"host":[http_hostname]}],"handle":[{"handler":"static_response","status_code":200,"body":"dynamic-ready"}],"terminal":True})
        connection = http.client.HTTPConnection("127.0.0.1",http_port,timeout=3)
        connection.request("GET","/",headers={"Host":http_hostname})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == b"dynamic-ready"
        assert response.getheader("Location") is None
        connection.close()
        for route_id in ids:
            admin("DELETE", f"/id/{route_id}")
            try:
                admin("GET",f"/id/{route_id}")
            except urllib.error.HTTPError as error:
                assert error.code == 404
            else:
                raise AssertionError("deleted automatic-certificate route remains")
        admin("PATCH",f"/id/nestlink-service-certificates-{node}/automate",[])
        assert admin("GET",f"/id/nestlink-service-certificates-{node}/automate") == []
        receipt = {"schema_version":1,"real_caddy_dynamic_nested_hostname_certificate":True,"tls_chain_and_san_verified":True,"explicit_http_server_no_redirect":True,"os_trust_installation_disabled":True,"route_removal_confirmed":True,"dedicated_certificate_subject_removal_confirmed":True,"public_acme_run":False,"rust_compilation_run":False}
        (output / "receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
        print(json.dumps(receipt,indent=2))
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
        for key_path in output.rglob("*.key"):
            if not key_path.resolve().is_relative_to(output.resolve()):
                raise RuntimeError("fixture key path escaped its owned output directory")
            key_path.unlink()

if __name__ == "__main__":
    main()
