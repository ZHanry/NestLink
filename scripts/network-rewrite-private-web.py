#!/usr/bin/env python3
"""Hosted L2: real private SDK, Caddy HTTPS and Chrome with explicit test trust.

This simulates public DNS with the hosted VM's hosts file and a short-lived CA.
It does not claim Internet/ACME, installed daemon login, or public L3 acceptance.
Only sanitized evidence is exported; capabilities, keys and profiles stay private.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

CADDY_SHA = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
ROLE = "web::hosted::caddy_browser_fixture_role"

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def private_json(path, value):
    pending = path.with_suffix(".pending")
    with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    pending.rename(path)

def wait_json(path, process=None, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        if process is not None and process.poll() is not None:
            raise RuntimeError("owned-fixture-ended-before-marker")
        time.sleep(.05)
    raise TimeoutError("owned-marker-timeout")

def run(command, **kwargs):
    return subprocess.run([str(part) for part in command], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout

def live_group(group):
    # A waited root process does not prove its Chrome/Caddy descendants have
    # exited. Observe the original session's process group before deleting keys
    # or profiles; zombies have already released their executable resources.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and fields[0] != "Z":
                return True
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return False

def stop_group(process):
    if process is None:
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
    deadline = time.monotonic() + 3
    while live_group(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--caddy", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    args = parser.parse_args()
    env = os.environ
    if (os.name != "posix" or os.geteuid() == 0 or env.get("GITHUB_ACTIONS") != "true"
        or env.get("RUNNER_ENVIRONMENT") != "github-hosted" or env.get("RUNNER_OS") != "Linux"
        or env.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"
        or not env.get("GITHUB_WORKFLOW_REF", "").startswith("ZHanry/NestLink/.github/workflows/private-web-gateway.yml@refs/")
        or re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is None):
        raise ValueError("R02: use the ordinary-user dedicated GitHub-hosted workflow")
    root = Path.cwd().resolve(); temp = Path(env["RUNNER_TEMP"]).resolve(); output = args.output.resolve()
    if not output.is_relative_to(temp) or output == temp or output.is_relative_to(root) or output.exists():
        raise ValueError("fresh evidence directory beneath RUNNER_TEMP required")
    output.mkdir(mode=0o700)
    if sha(args.caddy) != CADDY_SHA or json.loads((args.tools / "package.json").read_text())["version"] != "25.14.0":
        raise ValueError("use reviewed Caddy 2.11.7 and puppeteer-core 25.14.0")
    receipt = {"schema_version": 1, "passed": False, "evidence_level": "L2_hosted_real_sdk_caddy_chrome",
        "scope": "Simulated DNS and trusted test CA on one hosted VM; not public L3, ACME, physical platform or installed daemon login acceptance",
        "build_source": {"repository":env["GITHUB_REPOSITORY"],"source_revision":env["GITHUB_SHA"],"workflow_revision":env.get("GITHUB_WORKFLOW_SHA"),"run_id":env["GITHUB_RUN_ID"],"run_attempt":env["GITHUB_RUN_ATTEMPT"],"runner_environment":env["RUNNER_ENVIRONMENT"],"cargo_lock_sha256":sha(root/"Cargo.lock")},
        "execution": {"runner_environment":env["RUNNER_ENVIRONMENT"],"runner_uid":os.geteuid(),"started_unix_ms":int(time.time()*1000),"cases":{}},
        "tools": {"caddy_sha256":CADDY_SHA,"chrome_sha256":sha(args.chrome),"puppeteer_version":"25.14.0","runner_sha256":sha(__file__),"browser_probe_sha256":sha(root/"scripts/network-rewrite-private-web.cjs")},"cleanup":{},"error_code":None}
    private = Path(tempfile.mkdtemp(prefix="nestlink-w25-private-",dir=temp)); private.chmod(0o700)
    fixture = caddy = browser = None; streams = []
    hosts_line = None; ca_installed = nss_installed = False
    ca_name = f"NestLink-W25-{uuid.uuid4()}"; ca_system = Path("/usr/local/share/ca-certificates")/(ca_name+".crt")
    nss = Path.home()/".pki/nssdb"; admin_port = 0
    active = "hosted-source-build"
    def command(action):
        sequence = 1
        while (private/f"command-{sequence}.json").exists(): sequence += 1
        private_json(private/f"command-{sequence}.json",{"sequence":sequence,"action":action})
        return wait_json(private/f"ack-{sequence}.json",fixture,15)
    def admin(path, value=None):
        data = None if value is None else json.dumps(value).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{admin_port}{path}",data=data,headers={"Content-Type":"application/json","Origin":f"http://127.0.0.1:{admin_port}"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:
            body=response.read(1_048_577)
            if len(body)>1_048_576: raise ValueError("admin-observation-too-large")
            return response.status, json.loads(body) if body else None
    def https(origin, path="/.nestlink/ready", host=None, cookie=None, context=None):
        name=urlsplit(origin).hostname
        connection=http.client.HTTPSConnection(name,443,context=context or ssl.create_default_context(cafile=str(private/"root.pem")),timeout=5)
        try:
            headers={}
            if host: headers["Host"]=host
            if cookie: headers["Cookie"]=cookie
            connection.request("GET",path,headers=headers); response=connection.getresponse()
            return response.status,response.read(4097)
        finally: connection.close()
    try:
        build = subprocess.run(["cargo","test","--locked","-p","nestlink-sdk","--test","private_services","--no-run","--message-format=json-render-diagnostics"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (output/"build.log").write_bytes(build.stderr)
        (output/"build-messages.jsonl").write_bytes(build.stdout)
        if build.returncode: raise RuntimeError("hosted-rust-build-failed")
        artifacts=[]
        for line in build.stdout.decode().splitlines():
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            if item.get("reason")=="compiler-artifact" and item.get("target",{}).get("name")=="private_services" and item.get("executable"):
                artifacts.append(Path(item["executable"]))
        if len(artifacts)!=1: raise ValueError("exact-private-sdk-test-artifact-required")
        receipt["build_source"].update(test_executable_sha256=sha(artifacts[0]),command=["cargo","test","--locked","-p","nestlink-sdk","--test","private_services","--no-run"])
        fixture_log=open(private/"fixture.log","wb"); streams.append(fixture_log)
        active="original-private-sdk-fixture"
        fixture_env=env.copy();fixture_env.update(NESTLINK_PRIVATE_WEB_L2="1",NESTLINK_PRIVATE_WEB_DIRECTORY=str(private),NESTLINK_NODE_TEST_USAGE_ROOT=str(private))
        fixture=subprocess.Popen([str(artifacts[0]),"--ignored","--exact",ROLE,"--nocapture"],stdout=fixture_log,stderr=subprocess.STDOUT,env=fixture_env,start_new_session=True)
        ready=wait_json(private/"ready.json",fixture,40)
        services=ready["services"]
        active="hosted-os-name-and-test-ca-trust"
        if len(services)!=2: raise ValueError("two-original-private-services-required")
        names=[service["origin"].removeprefix("https://") for service in services]+["control.example.com","attacker.other.test"]
        if any(re.fullmatch(r"[a-z0-9.-]+",name) is None for name in names): raise ValueError("unexpected-fixture-hostname")
        hosts_line="127.0.0.1 "+" ".join(names)+f" # {ca_name}\n"
        run(["sudo","-n","tee","-a","/etc/hosts"],input=hosts_line.encode())
        if any(socket.gethostbyname(name)!="127.0.0.1" for name in names): raise ValueError("real-os-hosts-mapping-failed")
        run(["openssl","req","-x509","-newkey","rsa:2048","-sha256","-nodes","-days","1","-subj",f"/CN={ca_name}","-addext","basicConstraints=critical,CA:TRUE,pathlen:0","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",private/"root-key.pem","-out",private/"root.pem"])
        run(["openssl","req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=private.example.net","-keyout",private/"leaf-key.pem","-out",private/"leaf.csr"])
        (private/"leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:*.private.example.net,DNS:control.example.com,DNS:attacker.other.test\n")
        run(["openssl","x509","-req","-in",private/"leaf.csr","-CA",private/"root.pem","-CAkey",private/"root-key.pem","-CAcreateserial","-days","1","-sha256","-extfile",private/"leaf.ext","-out",private/"leaf.pem"])
        root_der=run(["openssl","x509","-in",private/"root.pem","-outform","DER"])
        with os.fdopen(os.open(private/"front-root.der",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as stream: stream.write(root_der)
        for path in private.glob("*.pem"): path.chmod(0o600)
        ca_installed=True;run(["sudo","-n","cp",private/"root.pem",ca_system])
        run(["sudo","-n","update-ca-certificates"])
        nss.mkdir(parents=True,exist_ok=True)
        if not (nss/"cert9.db").exists(): run(["certutil","-N","--empty-password","-d",f"sql:{nss}"])
        nss_installed=True;run(["certutil","-A","-d",f"sql:{nss}","-n",ca_name,"-t","C,,","-i",private/"root.pem"])
        with socket.socket() as listener: listener.bind(("127.0.0.1",0));admin_port=listener.getsockname()[1]
        routes=[]
        for index,service in enumerate(services):
            route=copy.deepcopy(service["route"]);route["@id"]=f"w25-{index}-{service['owner_id']}";routes.append(route)
        routes.extend([
            {"match":[{"host":["control.example.com"]}],"handle":[{"handler":"static_response","status_code":200,"body":"Management cookie sentinel","headers":{"Set-Cookie":["nl15_access=management-sentinel; Path=/; Secure; HttpOnly; SameSite=Strict"]}}],"terminal":True},
            {"match":[{"host":["attacker.other.test"]}],"handle":[{"handler":"static_response","status_code":200,"body":"Cross-origin test page"}],"terminal":True},
            {"handle":[{"handler":"static_response","status_code":404}],"terminal":True}])
        config={"admin":{"listen":f"127.0.0.1:{admin_port}","enforce_origin":True,"origins":[f"http://127.0.0.1:{admin_port}"],"config":{"persist":False}},"apps":{"http":{"servers":{"private":{"listen":[":443"],"strict_sni_host":True,"automatic_https":{"disable":True},"read_header_timeout":"2s","idle_timeout":"30s","max_header_bytes":32768,"tls_connection_policies":[{}],"routes":routes}}},"tls":{"certificates":{"load_files":[{"certificate":str(private/"leaf.pem"),"key":str(private/"leaf-key.pem")}]}}}}
        private_json(private/"caddy.json",config)
        active="actual-caddy-https-readiness"
        caddy_log=open(private/"caddy.log","wb");streams.append(caddy_log)
        caddy=subprocess.Popen([str(args.caddy),"run","--config",str(private/"caddy.json")],stdout=caddy_log,stderr=subprocess.STDOUT,start_new_session=True)
        deadline=time.monotonic()+15
        readiness={"attempts":0,"last_status":None,"owner_matched":False,"transport_error":None}
        receipt["execution"]["caddy_readiness"]=readiness
        while True:
            readiness["attempts"]+=1
            try:
                status,body=https(services[0]["origin"])
                readiness.update(last_status=status,owner_matched=body==services[0]["owner_id"].encode(),transport_error=None)
                if status==200 and readiness["owner_matched"]: break
            except (OSError,ssl.SSLError) as error:
                readiness["transport_error"]=type(error).__name__
            if time.monotonic()>deadline: raise TimeoutError("real-caddy-readiness-failed")
            time.sleep(.1)
        cases=receipt["execution"]["cases"]
        active="frontend-ca-and-sni-host-negative-cases"
        cases["real_os_name_mapping_and_frontend_ca_name"] = True
        untrusted=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try: https(services[0]["origin"],context=untrusted);raise AssertionError("untrusted-frontend-root-accepted")
        except ssl.SSLCertVerificationError: cases["untrusted_frontend_root_refused"]=True
        assert https(services[0]["origin"],host="control.example.com")[0]==421
        cases["sni_host_mismatch_refused"]=True
        for kind in ("root","name"):
            active=f"actual-caddy-wrong-upstream-{kind}"
            broken=copy.deepcopy(config);tls=broken["apps"]["http"]["servers"]["private"]["routes"][0]["handle"][0]["transport"]["tls"]
            if kind=="root":
                import base64
                tls["ca"]["trusted_ca_certs"]=[base64.b64encode(root_der).decode()]
            else: tls["server_name"]="wrong.private-web.nestlink.invalid"
            admin("/load",broken)
            assert https(services[0]["origin"])[0]==502
            cases[f"real_caddy_wrong_upstream_{kind}_refused"]=True
        admin("/load",config)
        active="production-sdk-https-readiness-before-ticket"
        launch=command("launch")["result"]
        assert launch["original_sdk_https_readiness"] is True
        private_json(private/"browser-input.json",{"services":[{"origin":service["origin"],"launch_url":url} for service,url in zip(services,launch["launch_urls"])],"management":"https://control.example.com","attacker":"https://attacker.other.test"})
        browser_log=open(private/"browser.log","wb");streams.append(browser_log)
        active="real-chrome-private-application-cases"
        browser=subprocess.Popen(["node",str(root/"scripts/network-rewrite-private-web.cjs"),"--directory",str(private),"--tools",str(args.tools),"--chrome",str(args.chrome)],stdout=browser_log,stderr=subprocess.STDOUT,start_new_session=True)
        if browser.wait(timeout=90)!=0: raise RuntimeError("real-browser-cases-failed")
        browser_report=wait_json(private/"browser-report.json",seconds=2)
        if not browser_report.get("passed"): raise AssertionError("browser-report-failed")
        receipt["execution"]["browser"]=browser_report
        active="stopped-owner-same-port-replacement"
        command("stop_first");command("start_replacement")
        old_cookie=json.loads((private/"browser-state.json").read_text())["old_cookie"]
        assert https(services[0]["origin"],"/me",cookie=old_cookie)[0]==502
        cases["old_caddy_route_replacement_endpoint_refused"]=True
        active="original-physical-and-quota-receipts"
        command("finish")
        if fixture.wait(timeout=20)!=0: raise RuntimeError("original-sdk-fixture-failed")
        physical=wait_json(private/"physical-receipt.json",seconds=2)
        replacement=physical["replacement"]
        assert replacement["rejected_tls_handshakes"]>0 and replacement["accepted_tls_handshakes"]==0 and replacement["application_bytes"]==0
        assert physical["host_carriers_joined"] and all(row["outstanding_bytes"]==0 for row in physical["original_quota_usage"])
        receipt["execution"]["physical_receipt"]=physical
        active="actual-caddy-route-removal-ack-readback"
        removed=copy.deepcopy(config);removed["apps"]["http"]["servers"]["private"]["routes"]=routes[2:]
        assert admin("/load",removed)[0]==200
        observed=admin("/config/apps/http/servers/private/routes")[1]
        assert not any(route.get("@id","").startswith("w25-") for route in observed)
        receipt["cleanup"]["caddy_route_delete_ack_and_readback"]=True
        receipt["passed"]=True
    except BaseException as error:
        receipt["error_code"]=type(error).__name__
        receipt["error_case"]=active
    finally:
        groups={}
        try: groups["browser"]=stop_group(browser)
        except BaseException: groups["browser"]=False
        if fixture is not None and fixture.poll() is None:
            try: command("finish");fixture.wait(timeout=15)
            except BaseException: pass
        for name,process in (("sdk_fixture",fixture),("caddy",caddy)):
            try: groups[name]=stop_group(process)
            except BaseException: groups[name]=False
        receipt["cleanup"]["owned_process_groups_empty"]=groups
        if not all(groups.values()): receipt["passed"]=False
        receipt["cleanup"]["owned_process_exit_codes"]={name:process.poll() for name,process in [("sdk_fixture",fixture),("caddy",caddy),("browser",browser)] if process is not None}
        if receipt["passed"] and any(code != 0 for code in receipt["cleanup"]["owned_process_exit_codes"].values()): receipt["passed"]=False
        for stream in streams: stream.close()
        # Debug output is bounded and redacted before entering an artifact.
        # Raw config/route/cookie/ticket/key/profile files are never exported.
        for name in ("fixture.log","caddy.log","browser.log"):
            path=private/name
            if path.exists():
                text=path.read_bytes()[-32768:].decode(errors="replace").replace(str(private),"[private-directory]")
                text=re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----","[redacted-pem]",text,flags=re.S)
                text=re.sub(r"[A-Za-z0-9_+/-]{32,}={0,2}","[redacted-opaque]",text)
                (output/(name+".sanitized.txt")).write_text(text)
        # Each cleanup is attempted even when another owned item failed.
        trust_cleanup={}
        try:
            if nss_installed: run(["certutil","-D","-d",f"sql:{nss}","-n",ca_name])
            trust_cleanup["nss_root_removed"]=True
        except BaseException: trust_cleanup["nss_root_removed"]=False
        try:
            if ca_installed:
                run(["sudo","-n","rm","--force","--",ca_system]);run(["sudo","-n","update-ca-certificates"])
            trust_cleanup["os_root_removed"]=True
        except BaseException: trust_cleanup["os_root_removed"]=False
        try:
            if hosts_line:
                current=Path("/etc/hosts").read_text();run(["sudo","-n","tee","/etc/hosts"],input=current.replace(hosts_line,"").encode())
                if ca_name in Path("/etc/hosts").read_text(): raise RuntimeError("test-hosts-entry-remains")
            trust_cleanup["owned_hosts_entry_removed"]=True
        except BaseException: trust_cleanup["owned_hosts_entry_removed"]=False
        receipt["cleanup"].update(trust_cleanup)
        receipt["cleanup"]["test_os_nss_trust_and_hosts_removed"]=all(trust_cleanup.values())
        if not all(trust_cleanup.values()): receipt["passed"]=False
        for name,key in (("browser-report.json","browser"),("physical-receipt.json","physical_receipt")):
            if (private/name).exists():
                try: receipt["execution"].setdefault(key,json.loads((private/name).read_text()))
                except BaseException: receipt["passed"]=False;receipt["cleanup"][key+"_readable"]=False
        try:
            shutil.rmtree(private)
            receipt["cleanup"]["private_capabilities_keys_and_profile_removed"]=True
        except BaseException: receipt["passed"]=False;receipt["cleanup"]["private_capabilities_keys_and_profile_removed"]=False
        receipt["execution"]["finished_unix_ms"]=int(time.time()*1000)
        (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print("Hosted private Web L2 evidence: "+str(output/"receipt.json"),flush=True)
    return 0 if receipt["passed"] else 1

if __name__=="__main__": raise SystemExit(main())
