#!/usr/bin/env python3
"""Actions-only signed native ICE / pinned Quinn / FileRead behind two SNATs.

Reuses the existing socket/routed experiment owners, ordinary-UID namespace
entrypoint, cleanup and provenance. No external NAT or installed-device claim.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import struct
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nestlink_routed_experiment", ROOT / "scripts/network-rewrite-routed.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing existing routed experiment owners")
ROUTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROUTED)
SOCKET, EVIDENCE, require = ROUTED.SOCKET, ROUTED.EVIDENCE, ROUTED.require
CASES = ("success", "blackhole", "cancel")
STUN = ("10.221.1.1", 3478)
COOKIE = b"\x21\x12\xa4\x42"


def packets(path: Path) -> list[dict]:
    """Reject truncated frames, IP fragments and offload-sized UDP records."""
    data = path.read_bytes()
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    require(len(data) >= 24 and data[:4] in orders, "missing classic pcap header")
    order = orders[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(order + "HHIIII", data[4:24])
    require((major, minor) == (2, 4) and snaplen >= 65535 and linktype == 1, "complete Ethernet capture required")
    offset, result = 24, []
    while offset < len(data):
        require(len(data) - offset >= 16, "truncated pcap packet header")
        _, _, included, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        require(included == original and 0 < included <= snaplen and offset + included <= len(data), "truncated captured frame")
        frame = data[offset:offset + included]
        offset += included
        require(len(frame) >= 42 and frame[12:14] == b"\x08\x00", "unexpected non-IPv4 UDP capture")
        ip = frame[14:]
        header, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        require(ip[0] >> 4 == 4 and header >= 20 and header + 8 <= total <= len(ip) and ip[9] == 17, "invalid IPv4 UDP framing")
        require(int.from_bytes(ip[6:8], "big") & 0x3fff == 0, "fragmented IP cannot qualify native ICE")
        udp = ip[header:total]
        require(int.from_bytes(udp[4:6], "big") == len(udp), "incomplete UDP datagram")
        payload = udp[8:]
        require(0 < len(payload) <= 1200, "physical UDP exceeds the frozen Quinn budget")
        result.append({"source":".".join(map(str, ip[12:16])), "destination":".".join(map(str, ip[16:20])),
                       "source_port":int.from_bytes(udp[:2], "big"), "destination_port":int.from_bytes(udp[2:4], "big"),
                       "payload":payload})
    require(result, "capture contained no actual UDP datagrams")
    return result


def stun_transaction(payload: bytes, kind: int) -> bytes | None:
    if len(payload) < 20 or payload[4:8] != COOKIE:
        return None
    require(int.from_bytes(payload[2:4], "big") + 20 == len(payload) and len(payload) % 4 == 0,
            "invalid STUN message length")
    return payload[8:20] if int.from_bytes(payload[:2], "big") == kind else None


def xor_mapped(payload: bytes, transaction: bytes) -> tuple[str, int]:
    require(stun_transaction(payload, 0x0101) == transaction, "STUN response transaction mismatch")
    offset, mapped = 20, None
    while offset < len(payload):
        require(len(payload) - offset >= 4, "truncated STUN attribute")
        kind, length = struct.unpack("!HH", payload[offset:offset + 4])
        end = offset + 4 + length
        require(end <= len(payload), "truncated STUN attribute value")
        value = payload[offset + 4:end]
        if kind == 0x20:
            require(mapped is None and len(value) == 8 and value[:2] == b"\x00\x01", "one IPv4 XOR-MAPPED-ADDRESS required")
            mapped = (".".join(str(a ^ b) for a, b in zip(value[4:], COOKIE)), int.from_bytes(value[2:4], "big") ^ 0x2112)
            require(mapped[1] > 0, "zero mapped port")
        offset = (end + 3) & ~3
    require(offset == len(payload) and mapped is not None, "missing complete XOR-MAPPED-ADDRESS")
    return mapped


def initial(payload: bytes) -> bool:
    if len(payload) < 1200 or payload[0] & 0xc0 != 0xc0:
        return False
    version, kind = int.from_bytes(payload[1:5], "big"), payload[0] & 0x30
    return (version == 1 and kind == 0) or (version == 0x6b3343cf and kind == 0x10)


def socket_address(value: str) -> tuple[str, int]:
    address, port = value.rsplit(":", 1)
    require(re.fullmatch(r"10\.(?:220|221)\.[12]\.[12]", address) is not None and port.isdecimal() and 0 < int(port) <= 65535,
            "unexpected owned socket address")
    return address, int(port)


def validate_role_receipts(name: str, roles: dict, source_sha256: str) -> None:
    require(name in CASES and set(roles) == {"controller", "host"}, "complete exact endpoint role pair required")
    for role, facts in roles.items():
        require(facts.get("role") == role and facts.get("passed") is True and facts.get("explicit_close_completed") is True,
                "missing successful original owner cleanup")
        addresses = facts.get("rebound_udp_addresses", [])
        require(len(addresses) == 2 and len(set(addresses)) == 2 and facts.get("released_udp_sockets") == 2,
                "both legacy and original ICE physical UDP sockets must be rebound")
        expected_ip = "10.220.1.2" if role == "controller" else "10.220.2.2"
        require(all(socket_address(value)[0] == expected_ip for value in addresses), "rebound address belongs to another endpoint")
        if name == "blackhole":
            require(facts.get("setup_rejected") is True and facts.get("uses_bilateral_ice") is False
                    and facts.get("payload_verified") is False and facts.get("file_bytes") == 0,
                    "blackholed peer route must never establish a business session")
        else:
            require(facts.get("uses_bilateral_ice") is True and facts.get("input_rejected") is True
                    and facts.get("input_rejection_code") == "permission_required"
                    and facts.get("payload_verified") is True and facts.get("file_bytes") == 262144,
                    "real bilateral ICE, 256KiB FileRead and Input denial are mandatory")
            digest = facts.get("payload_sha256")
            require(isinstance(digest, list) and len(digest) == 32 and all(type(v) is int and 0 <= v <= 255 for v in digest)
                    and bytes(digest).hex() == source_sha256, "FileRead digest differs from the original owned file")
            peer = socket_address(facts.get("selected_peer", ""))
            require(peer[0] == ("10.221.2.2" if role == "controller" else "10.221.1.2"), "selected peer is not the other SNAT address")
    if name == "cancel":
        require(roles["controller"].get("pending_read_cancelled") is True, "pending business read was not cancelled")


def prove_mapping(role: str, name: str, local_packets: list[dict], wan_packets: list[dict], facts: dict, peer: dict,
                  observations: list[dict]) -> dict:
    index = 1 if role == "controller" else 2
    legacy = 45000 + index
    sockets = [socket_address(value) for value in facts["rebound_udp_addresses"]]
    originals = [value for value in sockets if value[1] != legacy]
    require(len(originals) == 1 and (f"10.220.{index}.2", legacy) in sockets, "one original ICE socket and one legacy socket required")
    local_ip, local_port = originals[0]
    requests = [packet for packet in local_packets if packet["source"] == local_ip and packet["source_port"] == local_port
                and (packet["destination"], packet["destination_port"]) == STUN
                and stun_transaction(packet["payload"], 1) is not None]
    require(requests, "original ICE physical socket never sent STUN")
    mapping = None
    for packet in requests:
        transaction = stun_transaction(packet["payload"], 1)
        matches = [item for item in observations if bytes(item["transaction"]) == transaction]
        require(matches, "STUN server did not observe original socket transaction")
        for item in matches:
            candidate = socket_address(item["observed_source"])
            require(candidate[0] == f"10.221.{index}.2", "STUN reported the wrong independent gateway")
            translated = [p for p in wan_packets if (p["source"], p["source_port"]) == candidate
                          and (p["destination"], p["destination_port"]) == STUN
                          and stun_transaction(p["payload"], 1) == transaction]
            replies = [p for p in local_packets if (p["source"], p["source_port"]) == STUN
                       and p["destination"] == local_ip and p["destination_port"] == local_port
                       and stun_transaction(p["payload"], 0x0101) == transaction]
            require(translated and replies, "missing original/translated/request/response STUN capture pair")
            require(all(xor_mapped(p["payload"], transaction) == candidate for p in replies), "XOR-MAPPED-ADDRESS disagrees with kernel-observed source")
            require(mapping is None or mapping == candidate, "ICE physical socket changed its SNAT tuple")
            mapping = candidate
    require(mapping is not None, "missing actual ICE NAT mapping")
    destination = socket_address(facts["selected_peer"]) if name != "blackhole" else None
    peer_packets = [p for p in local_packets if p["source"] == local_ip and p["source_port"] == local_port
                    and p["destination"] == f"10.221.{3-index}.2"]
    require(peer_packets, "original ICE socket sent no actual peer connectivity checks")
    checks = sum(stun_transaction(p["payload"], 1) is not None for p in peer_packets)
    require(checks > 0, "missing actual same-socket ICE Binding checks")
    translated_peer = [p for p in wan_packets if (p["source"], p["source_port"]) == mapping
                       and p["destination"] == f"10.221.{3-index}.2"]
    require(translated_peer, "same-socket peer checks did not cross actual SNAT")
    initials = sum(initial(p["payload"]) for p in peer_packets)
    translated_initials = sum(initial(p["payload"]) for p in translated_peer)
    if name != "blackhole":
        if role == "controller":
            require(initials > 0 and translated_initials > 0, "no full-sized Quinn Initial used the STUN physical socket and mapping")
            require(any(a["payload"] == b["payload"] and a["destination_port"] == b["destination_port"]
                        for a in peer_packets if initial(a["payload"])
                        for b in translated_peer if initial(b["payload"])), "original and SNAT Quinn Initial payloads differ")
        require(socket_address(peer["selected_peer"]) == mapping, "peer's actual selected candidate differs from the observed mapping")
        require(all((p["destination"], p["destination_port"]) == destination for p in peer_packets), "peer socket dialed a non-selected destination")
    return {"original_socket":[local_ip,local_port], "observed_snat_socket":list(mapping),
            "stun_transactions":len(requests), "same_socket_peer_checks":checks,
            "same_socket_quic_initials":initials, "translated_quic_initials":translated_initials,
            "translated_peer_datagrams":len(translated_peer)}


def kernel_nat(experiment, name: str, namespace: str, mapping: dict) -> dict:
    local_ip, port = mapping["original_socket"]
    public_ip, public_port = mapping["observed_snat_socket"]
    record = experiment.command(name + "-conntrack", ["sudo","-n","ip","netns","exec",namespace,
        "conntrack","-L","-p","udp","-s",local_ip,"-d",STUN[0],"-o","extended"])
    text = (experiment.output / record["log"]).read_text()
    tuples = re.findall(r"\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)", text)
    require((local_ip,STUN[0],str(port),str(STUN[1])) in tuples
            and (STUN[0],public_ip,str(STUN[1]),str(public_port)) in tuples, "conntrack disagrees with captured STUN NAT mapping")
    counters = experiment.command(name + "-snat-counters", ["sudo","-n","ip","netns","exec",namespace,
        "iptables","-t","nat","-L","POSTROUTING","-n","-v","-x"])
    rows = re.findall(r"^\s*(\d+)\s+(\d+)\s+SNAT\s", (experiment.output / counters["log"]).read_text(), re.MULTILINE)
    require(len(rows) == 1 and int(rows[0][0]) > 0, "SNAT matched no real packets")
    return {"conntrack_log":record["log"], "counter_log":counters["log"],
            "nat_rule_packets":int(rows[0][0]), "nat_rule_bytes":int(rows[0][1])}


def case(experiment, executable: Path, name: str, private: Path) -> dict:
    facts = {"name":name,"passed":False,"failure":None,"started_at":EVIDENCE.utc_now(),
             "endpoint_processes":2,"control_stun_processes":1,"kernel_nat_namespaces":2,
             "cleanup_failures":[],"fault":None}
    fixture = private / name
    fixture.mkdir(mode=0o700)
    for role in ("controller","host"):
        (fixture / (role + ".seed")).write_bytes(secrets.token_bytes(32))
        (fixture / (role + ".seed")).chmod(0o600)
        (fixture / (role + ".id")).write_text(str(uuid.uuid4()))
    (fixture / "password").write_text(secrets.token_urlsafe(32))
    (fixture / "password").chmod(0o600)
    payload = secrets.token_bytes(262144)
    (fixture / "payload.bin").write_bytes(payload)
    facts["source_file"] = {"bytes":len(payload),"sha256":hashlib.sha256(payload).hexdigest()}
    token = secrets.token_hex(4)
    ns = {role:"ni-" + token + "-" + role for role in ("controller","host","central","nat1","nat2")}
    namespaces, links, captures = [], [], []
    endpoints, kernel_ids = {}, {}
    try:
        for role, namespace in ns.items():
            experiment.command(name+"-namespace-add", ["sudo","-n","ip","netns","add",namespace])
            namespaces.append(namespace)
            experiment.command(name+"-loopback", ["sudo","-n","ip","-n",namespace,"link","set","lo","up"])
            record = experiment.command(name+"-namespace-id", ["sudo","-n","ip","netns","exec",namespace,"readlink","/proc/self/ns/net"])
            ids = re.findall(r"^net:\[[0-9]+\]$", (experiment.output / record["log"]).read_text(), re.MULTILINE)
            require(len(ids) == 1, "missing actual kernel namespace identity")
            kernel_ids[role] = ids[0]
        require(len(set(kernel_ids.values())) == 5 and os.readlink("/proc/self/ns/net") not in kernel_ids.values(), "five distinct owned namespaces required")
        specs = (("controller","c","10.220.1.2","nat1","l1","10.220.1.1"),
                 ("nat1","w1","10.221.1.2","central","r1","10.221.1.1"),
                 ("host","h","10.220.2.2","nat2","l2","10.220.2.1"),
                 ("nat2","w2","10.221.2.2","central","r2","10.221.2.1"))
        for left, tag1, ip1, right, tag2, ip2 in specs:
            a, b = "v"+token+tag1, "v"+token+tag2
            experiment.command(name+"-veth-add", ["sudo","-n","ip","link","add",a,"type","veth","peer","name",b])
            links.extend((a,b))
            macs = {}
            for role, tag, interface, address in ((left,tag1,a,ip1),(right,tag2,b,ip2)):
                endpoints[tag] = (ns[role],interface,address)
                experiment.command(name+"-veth-move", ["sudo","-n","ip","link","set",interface,"netns",ns[role]])
                for argv in (["address","add",address+"/30","dev",interface], ["link","set",interface,"mtu","1280"], ["link","set",interface,"up"]):
                    experiment.command(name+"-interface", ["sudo","-n","ip","-n",ns[role],*argv])
                prefix = ["sudo","-n","ip","netns","exec",ns[role]]
                experiment.command(name+"-offloads-disable", [*prefix,"ethtool","-K",interface,"gro","off","gso","off","tso","off","tx-udp-segmentation","off"])
                state = experiment.command(name+"-offload-facts", [*prefix,"ethtool","-k",interface])
                text = (experiment.output / state["log"]).read_text()
                for feature in ("generic-receive-offload","generic-segmentation-offload","tx-udp-segmentation"):
                    require(re.search(r"^"+feature+r": off\b",text,re.MULTILINE) is not None, "capture offload remains enabled")
                link = ROUTED.output_json(experiment, experiment.command(name+"-link-facts", ["sudo","-n","ip","-j","-n",ns[role],"link","show","dev",interface]))
                require(len(link) == 1 and link[0].get("mtu") == 1280, "physical MTU differs from frozen topology")
                macs[role] = link[0]["address"]
            for role, interface, peer, address in ((left,a,right,ip2),(right,b,left,ip1)):
                experiment.command(name+"-neighbor", ["sudo","-n","ip","-n",ns[role],"neigh","replace",address,
                    "lladdr",macs[peer],"nud","permanent","dev",interface])
        for role, gateway in (("controller","10.220.1.1"),("host","10.220.2.1")):
            experiment.command(name+"-endpoint-route", ["sudo","-n","ip","-n",ns[role],"route","add","default","via",gateway])
        for index in (1,2):
            namespace = ns["nat"+str(index)]
            lan, wan = endpoints["l"+str(index)][1], endpoints["w"+str(index)][1]
            prefix = ["sudo","-n","ip","netns","exec",namespace]
            experiment.command(name+"-nat-route", ["sudo","-n","ip","-n",namespace,"route","add","10.221.0.0/16","via",f"10.221.{index}.1"])
            experiment.command(name+"-nat-forward", [*prefix,"sysctl","-w","net.ipv4.ip_forward=1"])
            for rule in (["-P","FORWARD","DROP"], ["-A","FORWARD","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"],
                         ["-A","FORWARD","-i",lan,"-o",wan,"-s",f"10.220.{index}.2","-d","10.221.0.0/16","-p","udp","-j","ACCEPT"],
                         ["-A","FORWARD","-i",lan,"-o",wan,"-s",f"10.220.{index}.2","-d",STUN[0],"-p","tcp","--dport","28880","-j","ACCEPT"],
                         ["-t","nat","-A","POSTROUTING","-o",wan,"-s",f"10.220.{index}.2","-j","SNAT","--to-source",f"10.221.{index}.2"]):
                experiment.command(name+"-owned-nat", [*prefix,"iptables",*rule])
        prefix = ["sudo","-n","ip","netns","exec",ns["central"]]
        experiment.command(name+"-central-route", [*prefix,"sysctl","-w","net.ipv4.ip_forward=1"])
        experiment.command(name+"-central-policy", [*prefix,"iptables","-P","FORWARD","DROP"])
        for first, second in ((1,2),(2,1)):
            experiment.command(name+"-central-peer", [*prefix,"iptables","-A","FORWARD","-s",f"10.221.{first}.2","-d",f"10.221.{second}.2",
                "-p","udp","-j","DROP" if name == "blackhole" else "ACCEPT"])
        if name == "blackhole":
            facts["fault"] = {"kind":"bidirectional-peer-udp-drop","stun_and_management_preserved":True,"installed_before_establish":True}
        for role in ("nat1","nat2","central"):
            routes = ROUTED.output_json(experiment, experiment.command(name+"-routes", ["sudo","-n","ip","-j","-n",ns[role],"route","show"]))
            require(not any(route.get("dst") == "default" for route in routes), "infrastructure namespace has external default route")
        facts["topology"] = {"namespaces":ns,"kernel_namespace_ids":kernel_ids,"runner_namespace":os.readlink("/proc/self/ns/net"),
            "kernel_nat":"two independent port-preserving SNAT gateways","link_mtu":1280,"external_route":False,
            "management_origin":"http://127.0.0.1:28880","central_stun":list(STUN),"endpoint_loopback_tcp_forwarders":True}
        for tag in ("c","h","w1","w2"):
            namespace, interface, _ = endpoints[tag]
            path = experiment.output / (name+"-"+tag+".pcap")
            entry = experiment.launch(name+"-capture-"+tag, ["sudo","-n","ip","netns","exec",namespace,"tcpdump","--immediate-mode",
                "-i",interface,"-nn","-s","0","-U","-Z",pwd.getpwuid(os.getuid()).pw_name,"-w",str(path),"udp"])
            captures.append((tag,path,entry))
            deadline = time.monotonic()+3
            while "listening on" not in (experiment.output / entry[2]["log"]).read_text(errors="replace"):
                require(entry[0].poll() is None and time.monotonic() < deadline, "capture never became ready")
                time.sleep(0.02)
        central = experiment.launch(name+"-central", SOCKET.namespace_argv(ns["central"], executable,"central",fixture,name))
        SOCKET.marker(fixture,"central-ready",(central,),timeout=15)
        controller = experiment.launch(name+"-controller", SOCKET.namespace_argv(ns["controller"],executable,"controller",fixture,name))
        host = experiment.launch(name+"-host", SOCKET.namespace_argv(ns["host"],executable,"host",fixture,name))
        active = (central,controller,host)
        if name != "blackhole":
            for marker in ("controller-established","host-established","controller-payload-verified","host-payload-verified"):
                SOCKET.marker(fixture,marker,active,timeout=25)
            if name == "cancel":
                SOCKET.marker(fixture,"host-request-received",active)
                facts["fault"] = SOCKET.drop_egress(experiment,name,ns["nat2"],endpoints["w2"][1],"host_nat_to_controller")
                SOCKET.write_marker(fixture,"fault-installed")
                SOCKET.marker(fixture,"host-response-sent",active)
                SOCKET.marker(fixture,"controller-read-blocked",active)
                SOCKET.write_marker(fixture,"cancel-now")
                SOCKET.marker(fixture,"controller-read-cancelled",active)
            SOCKET.write_marker(fixture,"stop-all")
        for role, entry in (("controller",controller),("host",host)):
            ROUTED.finish_role(experiment,entry,timeout=30,namespace=kernel_ids[role])
        SOCKET.write_marker(fixture,"central-stop")
        ROUTED.finish_role(experiment,central,namespace=kernel_ids["central"])
        roles = {role:json.loads((fixture / (role+"-receipt.json")).read_text()) for role in ("controller","host")}
        validate_role_receipts(name,roles,facts["source_file"]["sha256"])
        require((fixture / "controller-permit-digest").read_bytes() == (fixture / "host-permit-digest").read_bytes(), "endpoints used different business permits")
        central_facts = json.loads((fixture / "central-receipt.json").read_text())
        require(central_facts.get("passed") is True and central_facts.get("stun_uses_kernel_observed_source") is True
                and central_facts.get("released_udp_sockets") == 1, "central STUN/management owner did not complete")
        parsed = {}
        for tag, path, entry in list(captures):
            experiment.stop_capture(entry)
            captures.remove((tag,path,entry))
            parsed[tag] = packets(path)
        mappings = {}
        for role, local_tag, wan_tag, index in (("controller","c","w1",1),("host","h","w2",2)):
            mappings[role] = prove_mapping(role,name,parsed[local_tag],parsed[wan_tag],roles[role],roles["host" if role == "controller" else "controller"],central_facts["stun_observations"])
            mappings[role]["kernel_nat"] = kernel_nat(experiment,name+"-nat"+str(index),ns["nat"+str(index)],mappings[role])
            (experiment.output / (name+"-"+role+"-receipt.json")).write_text(json.dumps(roles[role],indent=2)+"\n")
        (experiment.output / (name+"-central-receipt.json")).write_text(json.dumps(central_facts,indent=2)+"\n")
        facts["roles"], facts["same_socket_mappings"] = roles, mappings
        if name in ("blackhole","cancel"):
            prefix = ["sudo","-n","ip","netns","exec",ns["central" if name == "blackhole" else "nat2"]]
            argv = ["iptables","-L","FORWARD","-n","-v","-x"] if name == "blackhole" else ["tc","-s","qdisc","show","dev",endpoints["w2"][1]]
            record = experiment.command(name+"-drop-counters",[*prefix,*argv])
            text = (experiment.output / record["log"]).read_text()
            drops = re.findall(r"^\s*(\d+)\s+\d+\s+DROP\s+udp\s",text,re.MULTILINE) if name == "blackhole" else re.findall(r"\bdropped (\d+)\b",text)
            require(drops and sum(map(int,drops)) > 0, "kernel did not drop any actual peer traffic")
            facts["fault"]["kernel_dropped_packets"] = sum(map(int,drops))
            facts["fault"]["kernel_counter_log"] = record["log"]
        facts["passed"] = True
    except BaseException as error:
        facts["failure"] = type(error).__name__+": "+str(error)
    finally:
        for _, _, entry in captures:
            if entry in experiment.active and entry[0].poll() is None:
                try:
                    experiment.stop_capture(entry)
                except BaseException as error:
                    facts["cleanup_failures"].append("capture: "+str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        for namespace in reversed(namespaces):
            try:
                record = experiment.command(name+"-remaining-pids",["sudo","-n","ip","netns","pids",namespace])
                pids = [line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:] if line.strip()]
                require(all(pid.isdecimal() for pid in pids), "invalid owned namespace PID inventory")
                if pids:
                    facts["cleanup_failures"].append(namespace+": process survived normal role completion")
                    experiment.command(name+"-force-owned-pids",["sudo","-n","kill","-KILL","--",*pids],accepted=(0,1))
                deadline = time.monotonic()+3
                while True:
                    record = experiment.command(name+"-remaining-pids-recheck",["sudo","-n","ip","netns","pids",namespace])
                    if not any(line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:]):
                        break
                    require(time.monotonic() < deadline, "namespace retained a live process")
                    time.sleep(0.05)
                experiment.command(name+"-namespace-delete",["sudo","-n","ip","netns","delete",namespace])
            except BaseException as error:
                facts["cleanup_failures"].append(namespace+": "+str(error))
        for interface in links:
            try:
                record = experiment.command(name+"-remaining-veth",["ip","link","show","dev",interface],accepted=(0,1))
                if record["return_code"] == 0:
                    experiment.command(name+"-partial-veth-delete",["sudo","-n","ip","link","delete",interface])
            except BaseException as error:
                facts["cleanup_failures"].append(interface+": "+str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        try:
            record = experiment.command(name+"-namespace-catalog",["ip","netns","list"])
            remaining = {line.split()[0] for line in (experiment.output / record["log"]).read_text().splitlines()[1:] if line.strip()}
            require(not remaining.intersection(namespaces), "owned namespace survived cleanup")
            facts["owned_namespaces_removed"] = True
        except BaseException as error:
            facts["cleanup_failures"].append("namespace catalog: "+str(error))
        facts["passed"] = facts["passed"] and not facts["cleanup_failures"]
        facts["finished_at"] = EVIDENCE.utc_now()
        (experiment.output / (name+"-receipt.json")).write_text(json.dumps(facts,indent=2)+"\n")
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    identity = EVIDENCE.validate_actions_environment(os.environ)
    require(sys.platform == "linux" and identity["runner"]["os"] == "Linux" and os.getuid() != 0, "ordinary GitHub-hosted Linux runner required")
    require(ROOT.resolve() == Path(os.environ["GITHUB_WORKSPACE"]).resolve(), "source must be GITHUB_WORKSPACE")
    output = EVIDENCE.validate_output_path(args.output,ROOT,Path(os.environ["RUNNER_TEMP"]))
    output.mkdir(parents=True)
    commands, processes, cases = [], [], []
    experiment = SOCKET.Experiment(output,commands,processes)
    before = after = executable_record = None
    failure = None
    try:
        before = EVIDENCE.source_snapshot(ROOT,identity["source_revision"])
        EVIDENCE.require_unchanged_source(before,before)
        experiment.command("tool-index",["sudo","-n","apt-get","update"],180)
        experiment.command("network-tools",["sudo","-n","apt-get","install","-y","--no-install-recommends",
            "iproute2","tcpdump","util-linux","iptables","conntrack","ethtool"],180)
        for label, argv in (("rust-version",["rustc","--version","--verbose"]),("cargo-version",["cargo","--version"]),
                            ("kernel",["uname","-a"]),("iptables-version",["iptables","--version"]),("conntrack-version",["conntrack","--version"])):
            experiment.command(label,argv)
        experiment.command("native-ice-boundaries",[sys.executable,"-B","-m","unittest","discover","-s","tests/network","-p","test_native_ice_evidence.py"])
        experiment.command("lint-native-ice-roles",["cargo","clippy","-p","nestlink-sdk","--locked","--test","network_native_ice","--","-D","warnings"],1200)
        built = experiment.command("build-native-ice-roles",["cargo","test","-p","nestlink-sdk","--locked","--test","network_native_ice","--no-run","--message-format=json"],1200)
        binaries = []
        for line in (output / built["log"]).read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target",{}).get("name") == "network_native_ice" and item.get("profile",{}).get("test") and item.get("executable"):
                binaries.append(Path(item["executable"]).resolve())
        require(len(binaries) == 1 and binaries[0].is_file(), "one freshly built native ICE role executable required")
        executable = binaries[0]
        executable_record = {"path":executable.relative_to(ROOT).as_posix(),"sha256":EVIDENCE.sha256_file(executable),
            "source_revision":identity["source_revision"],"dependency_lock_sha256":before["dependency_lock_sha256"]}
        with tempfile.TemporaryDirectory(prefix="nestlink-native-ice-private-",dir=os.environ["RUNNER_TEMP"]) as private:
            Path(private).chmod(0o700)
            for name in CASES:
                cases.append(case(experiment,executable,name,Path(private)))
        require(len(cases) == len(CASES) and all(item["passed"] for item in cases), "one or more real native ICE/SNAT cases failed")
    except BaseException as error:
        failure = type(error).__name__+": "+str(error)
    finally:
        cleanup = experiment.cleanup_processes()
        if cleanup:
            failure = (failure or "")+"; process cleanup: "+"; ".join(cleanup)
        try:
            after = EVIDENCE.source_snapshot(ROOT,identity["source_revision"])
            require(before is not None, "missing initial source snapshot")
            EVIDENCE.require_unchanged_source(before,after)
        except BaseException as error:
            failure = (failure or "")+"; source integrity: "+str(error)
        receipt = {"schema_version":1,"kind":"nestlink-native-ice-kernel-nat-experiment","passed":failure is None,"failure":failure,
            "scope":"signed SDK native ICE, pinned Quinn and 256KiB FileRead business-channel bytes across two real Linux SNATs",
            "ac04_passed":False,"ac05_passed":False,"ac07_passed":False,
            "build_provenance":{**identity,"source_before":before,"source_after":after,"executable":executable_record},
            "execution_provenance":{**identity,"environment":"github-hosted-linux-network-namespaces","process_uid":os.getuid()},
            "cases":cases,"commands":commands,"processes":processes,"files":EVIDENCE.artifact_files(output),
            "limitations":["Owned Linux port-preserving SNAT only; no external routers, symmetric NAT, CGNAT or IPv6 NAT qualification",
                "Actual signed remote SessionPermit, SDK signaling, bilateral ICE and pinned Quinn run; no screen, input injection, audio or installed Windows acceptance",
                "FileRead frames carry a complete owned random 256KiB payload in both directions; no file browser, filesystem grant, download/resume or file worker claim",
                "Both original legacy and ICE physical sockets must be rebound after explicit owner cleanup; success cannot fall back to legacy",
                "Management uses unchanged loopback-only HTTP development policy with namespace-local transparent TCP forwarders; no SDK TLS rules changed",
                "Credentials, identities, ICE passwords and signaling payloads remain in private temporary storage outside artifacts; captures contain UDP only"]}
        (output / "network-native-ice-evidence.json").write_text(json.dumps(receipt,indent=2)+"\n")
        print(json.dumps({"passed":receipt["passed"],"failure":failure,"evidence":str(output)},indent=2),flush=True)
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
