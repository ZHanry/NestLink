#!/usr/bin/env python3
"""Hosted L2: original SDK -> two real edges -> fixed kernel IPVS entry.

Uses isolated visitor/director/edge namespaces, real Caddy and keepalived.
DNS and CA are explicit local fixtures. This is not public Internet/ACME,
director HA, old-session continuity or physical deployment acceptance.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit
import uuid

CADDY_SHA = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
VIP = "11.254.2.10"  # Routed only inside the isolated fixture namespaces.
BACKENDS = ["10.244.1.11", "10.244.1.12"]
NAME = "application.svc.nestlink.test"
ROLE = "actual_ipvs_dual_edge_role"

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def run(command, **kwargs):
    return subprocess.run([str(part) for part in command], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout

def private_json(path, value):
    pending = path.with_suffix(".pending")
    with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    pending.rename(path)

def wait_json(path, process=None, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            try: return json.loads(path.read_text())
            except json.JSONDecodeError: pass
        if process is not None and process.poll() is not None:
            raise RuntimeError("original-role-ended-before-marker")
        time.sleep(.05)
    raise TimeoutError("original-role-marker-timeout")

def stop_group(process):
    if process is None: return
    if process.poll() is None:
        subprocess.run(["sudo", "-n", "kill", "-TERM", "--", f"-{process.pid}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: process.wait(timeout=6)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "-n", "kill", "-KILL", "--", f"-{process.pid}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.wait(timeout=5)
    deadline=time.monotonic()+3
    while group_alive(process.pid):
        subprocess.run(["sudo","-n","kill","-KILL","--",f"-{process.pid}"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if time.monotonic()>deadline: raise TimeoutError("owned-process-group-remains")
        time.sleep(.05)

def group_alive(group):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit(): continue
        try:
            fields=(entry/"stat").read_text().rsplit(")",1)[1].split()
            if int(fields[2])==group and fields[0]!="Z": return True
        except (FileNotFoundError,ProcessLookupError,PermissionError): pass
    return False

def kill_original_edge(process):
    # Kill the actual independently owned edge role, including NodeControl,
    # without running Rust Drop, edge shutdown or a fabricated usage seal.
    run(["sudo","-n","kill","-KILL","--",f"-{process.pid}"])
    process.wait(timeout=5)
    deadline=time.monotonic()+5
    while group_alive(process.pid):
        if time.monotonic()>deadline: raise TimeoutError("killed-original-edge-process-group-remains")
        time.sleep(.05)
    if process.returncode==0: raise AssertionError("SIGKILL-must-not-be-a-cooperative-success")

class Topology:
    def __init__(self):
        self.prefix = "n26" + uuid.uuid4().hex[:5]
        self.names = {name: self.prefix + "-" + name for name in ("director", "visitor", "edge1", "edge2")}
        self.bridge = self.prefix + "b"
        self.created = []; self.bridge_created = False; self.links = []
    def ns(self, name, *command):
        return ["sudo", "-n", "ip", "netns", "exec", self.names[name], *command]
    def inside(self, name, *command): return run(self.ns(name, *command))
    def setup(self):
        run(["sudo", "-n", "modprobe", "ip_vs"])
        run(["sudo", "-n", "modprobe", "ip_vs_wrr"])
        for name in self.names:
            run(["sudo", "-n", "ip", "netns", "add", self.names[name]])
            self.created.append(name); self.inside(name, "ip", "link", "set", "lo", "up")
        run(["sudo", "-n", "ip", "link", "add", self.bridge, "type", "bridge"]); self.bridge_created = True
        run(["sudo", "-n", "ip", "address", "add", "10.244.1.254/24", "dev", self.bridge])
        run(["sudo", "-n", "ip", "link", "set", self.bridge, "up"])
        for number, name in enumerate(("director", "edge1", "edge2")):
            host, peer = self.prefix + "b" + str(number), self.prefix + "p" + str(number)
            run(["sudo", "-n", "ip", "link", "add", host, "type", "veth", "peer", "name", peer])
            self.links.append(host)
            run(["sudo", "-n", "ip", "link", "set", peer, "netns", self.names[name]])
            run(["sudo", "-n", "ip", "link", "set", host, "master", self.bridge])
            run(["sudo", "-n", "ip", "link", "set", host, "up"])
            self.inside(name, "ip", "link", "set", peer, "name", "back0")
            address = "10.244.1.1" if name == "director" else BACKENDS[number-1]
            self.inside(name, "ip", "address", "add", address + "/24", "dev", "back0")
            self.inside(name, "ip", "link", "set", "back0", "up")
            if name != "director": self.inside(name, "ip", "route", "add", "default", "via", "10.244.1.1")
        direct, visitor = self.prefix + "df", self.prefix + "vf"
        run(["sudo", "-n", "ip", "link", "add", direct, "type", "veth", "peer", "name", visitor])
        self.links.append(direct)
        for peer, name, address in ((direct,"director","10.244.2.1"),(visitor,"visitor","10.244.2.2")):
            run(["sudo", "-n", "ip", "link", "set", peer, "netns", self.names[name]])
            self.inside(name, "ip", "link", "set", peer, "name", "front0")
            self.inside(name, "ip", "address", "add", address + "/24", "dev", "front0")
            self.inside(name, "ip", "link", "set", "front0", "up")
        self.inside("director", "ip", "address", "add", VIP + "/32", "dev", "front0")
        self.inside("visitor", "ip", "address", "add", "10.244.2.3/32", "dev", "front0")
        self.inside("visitor", "ip", "route", "add", VIP + "/32", "via", "10.244.2.1")
        for key, value in (("net.ipv4.ip_forward", "1"), ("net.ipv4.conf.all.rp_filter", "0"),
                ("net.ipv4.conf.front0.rp_filter", "0"), ("net.ipv4.conf.back0.rp_filter", "0"),
                ("net.ipv4.vs.expire_nodest_conn", "1"), ("net.ipv4.vs.expire_quiescent_template", "1")):
            self.inside("director", "sysctl", "-q", "-w", key + "=" + value)
        self.inside("director", "ipvsadm", "--set", "30", "5", "5")
        if self.inside("director", "ipvsadm", "-Sn").strip():
            raise ValueError("new-isolated-director-already-has-ipvs-owner")
    def close(self):
        failures = []
        for name in reversed(self.created):
            try: run(["sudo", "-n", "ip", "netns", "delete", self.names[name]])
            except subprocess.CalledProcessError: failures.append(name)
        for link in self.links:
            if subprocess.run(["sudo","-n","ip","link","show",link],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                try: run(["sudo","-n","ip","link","delete",link])
                except subprocess.CalledProcessError: failures.append(link)
        if self.bridge_created:
            try: run(["sudo", "-n", "ip", "link", "delete", self.bridge])
            except subprocess.CalledProcessError: failures.append(self.bridge)
        # Namespace deletion can concurrently remove its root veth peer after
        # the preceding presence read. A failed deletion is not completion;
        # verify actual absence of every exact owned name before acknowledging.
        deadline=time.monotonic()+3
        while True:
            links=json.loads(run(["sudo","-n","ip","-json","link","show"]))
            namespaces=json.loads(run(["sudo","-n","ip","-json","netns","list"]))
            remaining_links={entry["ifname"] for entry in links}.intersection(self.links+[self.bridge])
            remaining_namespaces={entry["name"] for entry in namespaces}.intersection(self.names.values())
            if not remaining_links and not remaining_namespaces: return
            if time.monotonic()>deadline: raise RuntimeError("owned-topology-absence-readback-failed")
            time.sleep(.05)

def certificate(directory):
    run(["openssl","req","-x509","-newkey","rsa:2048","-sha256","-nodes","-days","1","-subj","/CN=NestLink W26 isolated root","-addext","basicConstraints=critical,CA:TRUE,pathlen:0","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",directory/"root.key","-out",directory/"root.pem"])
    run(["openssl","req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+NAME,"-keyout",directory/"front.key","-out",directory/"front.csr"])
    (directory/"front.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"+NAME+",DNS:control.nestlink.test,DNS:doh.nestlink.test\n")
    run(["openssl","x509","-req","-in",directory/"front.csr","-CA",directory/"root.pem","-CAkey",directory/"root.key","-CAcreateserial","-days","1","-sha256","-extfile",directory/"front.ext","-out",directory/"front.pem"])
    (directory/"root.der").write_bytes(run(["openssl","x509","-in",directory/"root.pem","-outform","DER"]))
    for path in directory.iterdir():
        if path.is_file(): path.chmod(0o600)

class Dns:
    def __init__(self, directory, fixture, negative=False):
        group = fixture["group"]
        self.queries = []; queries = self.queries
        proof = "nestlink-group-v1:{}:{}:{}:{}:{}".format(fixture["deployment"],group["group_id"],
            group["revision"] + int(negative), group["service_id"],
            base64.urlsafe_b64encode(bytes.fromhex(fixture["aggregate_hex"])).decode().rstrip("="))
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                query = parse_qs(urlsplit(self.path).query)
                name, kind = query.get("name", [""])[0], int(query.get("type", ["0"])[0])
                queries.append((name,kind))
                answers = []
                if name == NAME and kind == 1: answers = [{"name":name,"type":kind,"TTL":30,"data":VIP}]
                elif name == "_nestlink-service." + NAME and kind == 16: answers = [{"name":name,"type":kind,"TTL":30,"data":'"'+proof+'"'}]
                body = json.dumps({"Status":0,"TC":False,"Question":[{"name":name,"type":kind}],"Answer":answers}).encode()
                self.send_response(200); self.send_header("Content-Type","application/dns-json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        class Server(ThreadingHTTPServer): allow_reuse_address = True; daemon_threads = True
        self.server = Server(("10.244.1.254",29443),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(directory/"front.pem",directory/"front.key")
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self): self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

def visitor(args):
    result={"passed":False,"error_type":None}
    payload=os.urandom(256); connection=None
    try:
        if args.protocol in ("http","https"):
            raw=socket.create_connection((VIP,443 if args.protocol=="https" else 80),timeout=1.5,source_address=(args.source,0))
            if args.protocol=="https":
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) if args.trust=="none" else ssl.create_default_context(cafile=str(args.root))
                raw=context.wrap_socket(raw,server_hostname=args.name)
            connection=http.client.HTTPConnection(args.name,timeout=1.5);connection.sock=raw
            connection.request("POST","/exchange",payload,{"Host":args.name,"Connection":"close","Content-Type":"application/octet-stream"})
            response=connection.getresponse();result["passed"]=response.status==200 and response.read(4096)==payload;result["status"]=response.status
        elif args.protocol=="tcp":
            connection=socket.create_connection((VIP,29100),timeout=1.5,source_address=(args.source,0));connection.sendall(payload);connection.shutdown(socket.SHUT_WR)
            received=bytearray()
            while len(received)<=2048:
                part=connection.recv(2048)
                if not part: break
                received.extend(part)
            result["passed"]=bytes(received)==payload
        else:
            connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);connection.settimeout(1.5);connection.bind((args.source,0));connection.connect((VIP,29100));connection.send(payload);result["passed"]=connection.recv(2048)==payload
    except (OSError,ssl.SSLError,http.client.HTTPException) as error: result["error_type"]=type(error).__name__
    finally:
        if connection is not None: connection.close()
    print(json.dumps(result));return 0

def hosted(args):
    env=os.environ
    if (os.name!="posix" or os.geteuid()==0 or env.get("GITHUB_ACTIONS")!="true"
        or env.get("RUNNER_ENVIRONMENT")!="github-hosted" or env.get("RUNNER_OS")!="Linux"
        or env.get("GITHUB_REPOSITORY")!="ZHanry/NestLink"
        or not env.get("GITHUB_WORKFLOW_REF","").startswith("ZHanry/NestLink/.github/workflows/service-group-ha.yml@refs/")
        or re.fullmatch(r"[0-9a-f]{40}",env.get("GITHUB_SHA","")) is None): raise ValueError("R02: use the ordinary-user dedicated GitHub-hosted workflow")
    root=Path.cwd().resolve();temp=Path(env["RUNNER_TEMP"]).resolve();output=args.output.resolve()
    if output.exists() or output==temp or not output.is_relative_to(temp) or output.is_relative_to(root): raise ValueError("fresh RUNNER_TEMP evidence directory required")
    output.mkdir(mode=0o700)
    if sha(args.caddy)!=CADDY_SHA: raise ValueError("reviewed Caddy 2.11.7 binary required")
    private=Path(tempfile.mkdtemp(prefix="nestlink-w26-private-",dir=temp));private.chmod(0o700)
    topology=Topology();processes=[];streams=[];dns=None;hosts_line=None
    receipt={"schema_version":1,"passed":False,"evidence_level":"L2_hosted_actual_ipvs_keepalived_dual_edge","scope":"Isolated Linux routing, DNS and operator CA; not public Internet/ACME, director HA, physical deployment or old-session continuity","build_provenance":{"source_revision":env["GITHUB_SHA"],"workflow_revision":env.get("GITHUB_WORKFLOW_SHA"),"run_id":env["GITHUB_RUN_ID"],"run_attempt":env["GITHUB_RUN_ATTEMPT"],"runner_environment":env["RUNNER_ENVIRONMENT"],"cargo_lock_sha256":sha(root/"Cargo.lock")},"execution_provenance":{"runner_environment":env["RUNNER_ENVIRONMENT"],"protocols":{},"crash_protocols":{},"started_unix_ms":int(time.time()*1000)},"tools":{"caddy_sha256":CADDY_SHA,"runner_sha256":sha(__file__)},"cleanup":{},"error_code":None}
    active="hosted-source-build"
    username=pwd.getpwuid(os.geteuid()).pw_name
    def spawn(command, path, extra_env=None):
        stream=open(path,"wb");streams.append(stream)
        process=subprocess.Popen([str(part) for part in command],stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,env=extra_env,start_new_session=True);processes.append(process);return process
    def ns_user(name, command): return topology.ns(name,"runuser","-u",username,"--",*command)
    def role(binary,directory,name,index=None,instance="initial"):
        protocol="http" if directory.name=="dns-stale" else directory.name.removeprefix("crash-")
        values={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted","RUST_BACKTRACE":"0","NESTLINK_GROUP_L2":"1","NESTLINK_GROUP_L2_ROLE":name,"NESTLINK_GROUP_L2_DIRECTORY":str(directory),"NESTLINK_GROUP_L2_PROTOCOL":protocol}
        if index is not None: values.update(NESTLINK_GROUP_L2_EDGE=str(index),NESTLINK_GROUP_L2_INSTANCE=instance)
        command=[str(binary),"--ignored","--exact",ROLE,"--nocapture"]
        if index is None:
            child_env=env.copy();child_env.update(values);return spawn(command,directory/"coordinator.log",child_env)
        return spawn(ns_user("edge"+str(index+1),["env",*[key+"="+value for key,value in values.items()],*command]),directory/(f"edge{index+1}-{instance}.log"))
    def request(directory, protocol, source="10.244.2.2",trust="root",name=NAME):
        return json.loads(run(ns_user("visitor",["env","GITHUB_ACTIONS=true","RUNNER_ENVIRONMENT=github-hosted","python3",str(root/"scripts/network-rewrite-service-group.py"),"--visitor","--protocol",protocol,"--source",source,"--root",str(directory/"root.pem"),"--trust",trust,"--name",name])))
    def admin(index,node,scheme):
        body=topology.inside("edge"+str(index+1),"curl","--fail","--silent","--show-error","--max-time","2","--noproxy","*","-H","Origin: http://127.0.0.1:2019",f"http://127.0.0.1:2019/id/nestlink-services-{scheme}-{node}/handle/0/routes")
        return json.loads(body)
    def health(index,path):
        command=topology.ns("director","curl","--silent","--max-time","2","--noproxy","*","--output","/dev/null","--write-out","%{http_code}",f"http://{BACKENDS[index]}:29201{path}")
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE);return result.stdout.decode()
    def stats():
        text=topology.inside("director","ipvsadm","-Ln","--stats","--exact").decode();counts={}
        for line in text.splitlines():
            fields=line.split()
            if fields and fields[0]=="->": counts[fields[1].rsplit(":",1)[0]]=int(fields[2])
        return text,counts
    try:
        build=subprocess.run(["cargo","test","--locked","-p","nestlink-sdk","--test","service_group_l2","--no-run","--message-format=json-render-diagnostics"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (output/"build.log").write_bytes(build.stderr);(output/"build-messages.jsonl").write_bytes(build.stdout)
        if build.returncode: raise RuntimeError("hosted-rust-build-failed")
        artifacts=[]
        for line in build.stdout.decode().splitlines():
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            if item.get("reason")=="compiler-artifact" and item.get("target",{}).get("name")=="service_group_l2" and item.get("executable"): artifacts.append(Path(item["executable"]))
        if len(artifacts)!=1: raise ValueError("exact-original-sdk-test-artifact-required")
        binary=artifacts[0];receipt["build_provenance"]["test_executable_sha256"]=sha(binary)
        active="isolated-kernel-topology";topology.setup()
        hosts_line="10.244.1.254 doh.nestlink.test # "+topology.prefix+"\n";run(["sudo","-n","tee","-a","/etc/hosts"],input=hosts_line.encode())
        receipt["tools"]["keepalived_version"]=subprocess.run(["keepalived","--version"],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.decode(errors="replace")[:2048]
        for phase in ("http","https","tcp","udp","crash-http","crash-https","crash-tcp","crash-udp","dns-stale"):
            crash=phase.startswith("crash-")
            protocol="http" if phase=="dns-stale" else phase.removeprefix("crash-")
            active=phase+"-original-owner-setup";directory=private/phase;directory.mkdir(mode=0o700);certificate(directory)
            coordinator=role(binary,directory,"coordinator");fixture=wait_json(directory/"fixture.json",coordinator,25)
            config=(directory/"frontdoor"/"keepalived.conf").read_text()
            matched=re.search(r"/service-group/([^/]+)/([0-9]+)/([0-9a-f]{64})",config)
            if matched is None: raise ValueError("original-exported-health-binding-missing")
            fixture["aggregate_hex"]=matched[3];health_path=matched[0]
            dns=Dns(directory,fixture,negative=phase=="dns-stale");proxy=[];caddies=[];edges=[]
            for index in range(2):
                name="edge"+str(index+1)
                proxy.append(spawn(topology.ns(name,"socat","TCP4-LISTEN:29200,bind=127.0.0.1,reuseaddr,fork","TCP4:10.244.1.254:29200"),directory/(name+"-control-proxy.log")))
                caddies.append(spawn(ns_user(name,["env","XDG_DATA_HOME="+str(directory/name/"data"),"XDG_CONFIG_HOME="+str(directory/name/"config"),str(args.caddy),"run","--config",str(directory/name/"Caddy.json")]),directory/(name+"-caddy.log")))
                deadline=time.monotonic()+10
                while True:
                    try:
                        if admin(index,fixture["edges"][index]["node_id"],"http")==[]: break
                    except (subprocess.CalledProcessError,json.JSONDecodeError): pass
                    if time.monotonic()>deadline: raise TimeoutError("original-caddy-bootstrap-not-ready")
                    time.sleep(.05)
                edges.append(role(binary,directory,"edge",index));wait_json(directory/name/"initial"/"ready.json",edges[-1],15)
            sequence=0
            def command(action,seconds=25,**payload):
                nonlocal sequence
                sequence+=1;private_json(directory/f"command-{sequence}.json",{"action":action,**payload});return wait_json(directory/f"ack-{sequence}.json",coordinator,seconds)["result"]
            if phase=="dns-stale":
                active="actual-caddy-stale-group-dns-proof"
                rejected=command("publish_reject",30)
                assert rejected["invalid_dns_group_revision_never_became_ready"]
                assert all(dns.queries.count(item)>=2 for item in [(NAME,1),(NAME,28),("_nestlink-service."+NAME,16)])
                assert all(health(index,health_path)!="200" for index in range(2))
                for index in range(2):
                    for scheme in ("http","https"): assert admin(index,fixture["edges"][index]["node_id"],scheme)==[]
                    marker=directory/("edge"+str(index+1))/"initial";private_json(marker/"stop.json",{});wait_json(marker/"stopped.json",edges[index],15)
                physical=command("finish",20);coordinator.wait(timeout=12);assert coordinator.returncode==0
                for index in range(2):
                    marker=directory/("edge"+str(index+1))/"initial";private_json(marker/"finish.json",{});edges[index].wait(timeout=12);assert edges[index].returncode==0
                receipt["execution_provenance"]["dns_stale_negative"]={"wrong_group_revision_txt_refused":True,"both_edges_queried_real_https_dns":True,"original_backend_requests":0,"route_delete_ack_readback":True,"physical_receipt":physical}
                dns.close();dns=None
                for process in caddies+proxy: stop_group(process)
                continue
            active=protocol+"-original-sdk-dual-publication";command("publish",40)
            keepalived=spawn(topology.ns("director","keepalived","--dont-fork","--check","--log-console","--use-file="+str(directory/"frontdoor"/"keepalived.conf"),"--pid="+str(directory/"keepalived.pid"),"--checkers_pid="+str(directory/"checkers.pid")),directory/"keepalived.log")
            deadline=time.monotonic()+12
            while [health(i,health_path) for i in range(2)]!=["200","200"]:
                if time.monotonic()>deadline: raise TimeoutError("exact-original-owner-health-not-ready")
                time.sleep(.1)
            wrong=health_path.replace("/1/","/2/")
            assert all(health(index,wrong)!="200" for index in range(2))
            active=protocol+"-actual-fixed-entry-both-members";deadline=time.monotonic()+15;success=0
            while True:
                success+=int(request(directory,protocol)["passed"])
                snapshot,counts=stats()
                if success>=8 and all(counts.get(ip,0)>0 for ip in BACKENDS): break
                if time.monotonic()>deadline: raise TimeoutError("actual-fixed-entry-did-not-use-both-edges")
            (output/(phase+"-ipvs-before.txt")).write_text(snapshot)
            cases={"original_sdk_dual_member_ready":True,"actual_ipvs_both_members_have_connections":True,"wrong_group_revision_health_refused":True,"initial_successful_new_requests":success}
            active=protocol+"-visitor-source-acl";before=command("observe")["backend_requests"]
            assert not request(directory,protocol,source="10.244.2.3")["passed"]
            after=command("observe")["backend_requests"];assert before==after
            cases["original_source_acl_allowed_visitor_and_denied_other_source"]=True
            if protocol=="https":
                active="https-front-root-and-name-negatives"
                assert request(directory,protocol,trust="none")["error_type"]=="SSLCertVerificationError"
                assert request(directory,protocol,name="wrong.svc.nestlink.test")["error_type"]=="SSLCertVerificationError"
                cases.update(untrusted_frontend_root_refused=True,wrong_frontend_name_refused=True)
            active=protocol+"-active-edge-owner-failure-caddy-stays-up"
            _,before_counts=stats();assert request(directory,protocol)["passed"];_,after_counts=stats()
            selected=next(index for index,ip in enumerate(BACKENDS) if after_counts.get(ip,0)>before_counts.get(ip,0));healthy=1-selected
            marker=directory/("edge"+str(selected+1))/"initial";started=time.monotonic()
            if crash:
                kill_original_edge(edges[selected]);assert not (marker/"stopped.json").exists()
                cases.update(failure_mode="SIGKILL",original_edge_process_group_dead=True,original_edge_exit_code=edges[selected].returncode)
            else:
                private_json(marker/"stop.json",{});cases["failure_mode"]="cooperative_original_owner_stop"
            deadline=started+30;recovered=None
            while time.monotonic()<deadline:
                result=request(directory,protocol)
                if result["passed"] and health(selected,health_path)!="200" and BACKENDS[selected] not in stats()[1]: recovered=time.monotonic()-started;break
                time.sleep(.1)
            if recovered is None: raise TimeoutError("new-connection-recovery-exceeded-30-seconds")
            if not crash: wait_json(marker/"stopped.json",edges[selected],15)
            assert caddies[selected].poll() is None and caddies[healthy].poll() is None
            if not crash: assert admin(selected,fixture["edges"][selected]["node_id"],"https" if protocol=="https" else "http")==[]
            elif protocol in ("http","https"):
                assert admin(selected,fixture["edges"][selected]["node_id"],protocol)!=[]
                cases["crashed_caddy_route_retained_until_original_reconcile"]=True
            # Continue real new visitor tuples after the failure. A still-open
            # Caddy TCP listener must never qualify its stopped original owner.
            for _ in range(6): assert request(directory,protocol)["passed"]
            cases.update(failed_node_id=fixture["edges"][selected]["node_id"],new_connection_recovery_seconds=recovered,caddy_process_remained_running=True,failed_edge_route_removed_before_restore=not crash,healthy_sibling_new_requests=True)
            crash_observation=command("observe_crash",member_index=selected) if crash else None
            active=protocol+"-all-member-revocation-and-old-edge-restore";command("revoke")
            for index in range(2):
                if crash and index==selected: continue
                for scheme in ("http","https"): assert admin(index,fixture["edges"][index]["node_id"],scheme)==[]
            assert not request(directory,protocol)["passed"]
            if not crash:
                private_json(marker/"finish.json",{});edges[selected].wait(timeout=12);assert edges[selected].returncode==0
            restored=role(binary,directory,"edge",selected,"restored");restored_marker=directory/("edge"+str(selected+1))/"restored";wait_json(restored_marker/"ready.json",restored,15)
            deadline=time.monotonic()+10
            while health(selected,health_path)!="503" or any(admin(selected,fixture["edges"][selected]["node_id"],scheme)!=[] for scheme in ("http","https")):
                if time.monotonic()>deadline: raise TimeoutError("restored-original-controller-did-not-reconcile-old-route")
                time.sleep(.05)
            assert health(selected,health_path)!="200" and not request(directory,protocol)["passed"]
            for scheme in ("http","https"): assert admin(selected,fixture["edges"][selected]["node_id"],scheme)==[]
            private_json(restored_marker/"stop.json",{});wait_json(restored_marker/"stopped.json",restored,15);private_json(restored_marker/"finish.json",{});restored.wait(timeout=12);assert restored.returncode==0
            other_marker=directory/("edge"+str(healthy+1))/"initial";private_json(other_marker/"stop.json",{});wait_json(other_marker/"stopped.json",edges[healthy],15)
            physical=command("finish",20);coordinator.wait(timeout=12);assert coordinator.returncode==0
            private_json(other_marker/"finish.json",{});edges[healthy].wait(timeout=12);assert edges[healthy].returncode==0
            cases.update(all_member_route_delete_ack_readback=True,revocation_blocks_fixed_entry=True,new_runtime_cannot_revive_old_group=True,original_four_scope_and_member_quota_sealed=not crash,original_usage_store_closed=True)
            if crash:
                assert physical["failed_runtime_unsealed_promise_retained"] and physical["healthy_original_grant_sealed"]
                assert physical["outstanding_bytes"]==crash_observation["original_failed_node_usage"]["outstanding_bytes"]>0
                cases.update(unknown_failed_slice_retained_without_new_grant=True,healthy_original_slice_sealed=True)
            else: assert physical["outstanding_bytes"]==0
            receipt["execution_provenance"]["crash_protocols" if crash else "protocols"][protocol]={"cases":cases,"crash_observation":crash_observation,"physical_receipt":physical}
            (output/(phase+"-ipvs-after.txt")).write_text(stats()[0])
            dns.close();dns=None;stop_group(keepalived)
            for process in caddies+proxy: stop_group(process)
            # This entire namespace was created by this fixture; the mature
            # owner has exited before its otherwise isolated table is cleared.
            topology.inside("director","ipvsadm","--clear")
        receipt["passed"]=True
    except BaseException as error:
        receipt["error_code"]=type(error).__name__;receipt["error_case"]=active
    finally:
        if dns is not None:
            try: dns.close()
            except BaseException: receipt["passed"]=False
        stopped=True
        for process in reversed(processes):
            try: stop_group(process)
            except BaseException: stopped=False
        for stream in streams: stream.close()
        receipt["cleanup"]["owned_processes_joined"]=stopped
        if not stopped: receipt["passed"]=False
        # Export bounded sanitized diagnostics only. Private config, target
        # choices, identities, TLS keys and database contents never leave tmp.
        for path in private.rglob("*.log"):
            text=path.read_bytes()[-32768:].decode(errors="replace").replace(str(private),"[private-directory]")
            text=re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----","[redacted-pem]",text,flags=re.S)
            text=re.sub(r"[A-Za-z0-9_+/-]{32,}={0,2}","[redacted-opaque]",text)
            (output/("-".join(path.relative_to(private).parts)+".sanitized.txt")).write_text(text)
        try:
            if hosts_line:
                current=Path("/etc/hosts").read_text();run(["sudo","-n","tee","/etc/hosts"],input=current.replace(hosts_line,"").encode())
                assert topology.prefix not in Path("/etc/hosts").read_text()
            receipt["cleanup"]["owned_hosts_mapping_removed"]=True
        except BaseException: receipt["passed"]=False;receipt["cleanup"]["owned_hosts_mapping_removed"]=False
        try: topology.close();receipt["cleanup"]["owned_namespaces_and_bridge_removed"]=True
        except BaseException: receipt["passed"]=False;receipt["cleanup"]["owned_namespaces_and_bridge_removed"]=False
        try: shutil.rmtree(private);receipt["cleanup"]["private_keys_configs_and_databases_removed"]=True
        except BaseException: receipt["passed"]=False;receipt["cleanup"]["private_keys_configs_and_databases_removed"]=False
        receipt["execution_provenance"]["finished_unix_ms"]=int(time.time()*1000)
        (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print("Hosted dual-edge fixed-entry L2 evidence: "+str(output/"receipt.json"),flush=True)
    return 0 if receipt["passed"] else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path);parser.add_argument("--caddy",type=Path)
    parser.add_argument("--visitor",action="store_true");parser.add_argument("--protocol",choices=("http","https","tcp","udp"));parser.add_argument("--source",default="10.244.2.2");parser.add_argument("--root",type=Path);parser.add_argument("--trust",choices=("root","none"),default="root");parser.add_argument("--name",default=NAME)
    args=parser.parse_args()
    if args.visitor:
        if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted": raise ValueError("hosted visitor role only")
        return visitor(args)
    if args.output is None or args.caddy is None: parser.error("--output and --caddy are required")
    return hosted(args)

if __name__=="__main__": raise SystemExit(main())
