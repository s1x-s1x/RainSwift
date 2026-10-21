"""Measure the private TLS harness over isolated Linux veth/netem TCP links.

The kernel support probe creates only uniquely named network namespaces. It never
changes the host default route, interfaces, sysctls or global traffic control.
Unsupported kernel features are failures, not user-space delay substitutes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import uuid
from workload_guard import performance_exclusive, require_quiet

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(argv, log, *, allowed_failure=False):
    started = time.monotonic()
    result = subprocess.run([str(x) for x in argv], text=True, capture_output=True, timeout=15)
    row = {"argv": [str(x) for x in argv], "exit_code": result.returncode,
           "stdout": result.stdout, "stderr": result.stderr,
           "elapsed_seconds": time.monotonic() - started}
    log.append(row)
    if result.returncode and not allowed_failure:
        raise RuntimeError(f"kernel command failed: {argv}: {result.stderr.strip()}")
    return row


class IsolatedLink:
    def __init__(self, log, *, rtt_ms=20):
        tag = uuid.uuid4().hex[:10]
        self.names = ["a15c-" + tag, "a15s-" + tag]
        self.client, self.server = self.names
        self.interfaces = ["a15c" + tag, "a15s" + tag]
        self.client_address, self.server_address = "198.18.0.1", "198.18.0.2"
        self.log, self.rtt_ms, self.created = log, rtt_ms, []
        self.pair_created = False

    def ns(self, name, *argv, **options):
        return command(["ip", "netns", "exec", name, *argv], self.log, **options)

    def __enter__(self):
        try:
            for name in self.names:
                command(["ip", "netns", "add", name], self.log)
                self.created.append(name)
            command(["ip", "link", "add", self.interfaces[0], "type", "veth", "peer", "name", self.interfaces[1]], self.log)
            self.pair_created = True
            for interface, namespace, address in zip(self.interfaces, self.names,
                    (self.client_address, self.server_address)):
                command(["ip", "link", "set", interface, "netns", namespace], self.log)
                self.ns(namespace, "ip", "link", "set", "lo", "up")
                self.ns(namespace, "ip", "link", "set", interface, "mtu", "1500")
                self.ns(namespace, "ip", "address", "add", address + "/24", "dev", interface)
                self.ns(namespace, "ip", "link", "set", interface, "up")
                # Packet captures must show kernel segmentation, not GRO/GSO
                # super-packets. Only these newly created veths are changed.
                self.ns(namespace, "ethtool", "-K", interface, "tso", "off", "gso", "off", "gro", "off")
                self.ns(namespace, "tc", "qdisc", "add", "dev", interface, "root", "netem", "delay",
                        str(self.rtt_ms / 2) + "ms", "limit", "1000")
            for interface, namespace, peer in zip(self.interfaces, self.names,
                    (self.server_address, self.client_address)):
                self.ns(namespace, "ip", "route", "replace", peer + "/32", "dev", interface, "initcwnd", "10")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in reversed(self.created):
            command(["ip", "netns", "delete", name], self.log, allowed_failure=True)
        self.created.clear()
        if self.pair_created:
            # Setup may fail before either endpoint has entered its namespace.
            # Delete only this run's UUID names; never enumerate host devices.
            for interface in self.interfaces:
                existing = command(["ip", "link", "show", "dev", interface], self.log, allowed_failure=True)
                if existing["exit_code"] == 0:
                    command(["ip", "link", "delete", "dev", interface], self.log)
            self.pair_created = False

    def __exit__(self, *unused):
        self.close()

    def delay(self, rtt_ms):
        for interface, namespace in zip(self.interfaces, self.names):
            self.ns(namespace, "tc", "qdisc", "change", "dev", interface, "root", "netem", "delay",
                    str(rtt_ms / 2) + "ms", "limit", "1000")


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def append_json(path, value):
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def source_hashes():
    paths = [Path(__file__), ROOT / "tools/native.py", ROOT / "tools/signing_budget.py", ROOT / "tools/workload_guard.py"]
    paths += list((ROOT / "base_tls/tls").rglob("*.py"))
    paths += list((ROOT / "c").rglob("*.c")) + list((ROOT / "c").rglob("*.h")) + [ROOT / "c/Makefile"]
    paths += list((ROOT / "third_party/slhdsa-c").rglob("*.c")) + list((ROOT / "third_party/slhdsa-c").rglob("*.h"))
    paths += [ROOT / "base_tls/requirements.lock.txt", ROOT / "base_tls/requirements-falcon.lock.txt"]
    provider = ROOT / "base_tls/.deps-falcon/installation.json"
    if provider.is_file():
        paths.append(provider)
        paths += [p for p in provider.parent.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(set(paths))}


def tree_hashes(directory):
    return {str(p.relative_to(directory)): sha(p) for p in sorted(Path(directory).rglob("*")) if p.is_file()}


def frame(payload):
    return len(payload).to_bytes(4, "big") + payload


def imports():
    sys.path.insert(0, str(ROOT / "base_tls"))
    from cryptography import x509
    from tls.alt_profiles import profiles
    from tls.credentials import CertificateAuthority, ServerCredentials
    from tls.handshake.client import HybridClient
    from tls.handshake.server import HybridServer
    from tls.record.aead import CONTENT_TYPE_APPLICATION_DATA
    from tls.transport.tcp import _recv_frame, _frame_deadline
    return x509, profiles, CertificateAuthority, ServerCredentials, HybridClient, HybridServer, CONTENT_TYPE_APPLICATION_DATA, _recv_frame, _frame_deadline


def server_worker(args):
    x509, profiles, Authority, Credentials, _, Server, app_type, recv_frame, deadline_for = imports()
    configs = profiles(args.fixtures, handshake_signer=args.handshake_signer)
    prepared = {}
    for code in args.profiles:
        config = configs[code]
        authority = Authority(config.classical())
        credentials = Credentials(config)
        prepared[code] = (config, authority, credentials, credentials.bind_to(authority))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.address, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)
    write_json(args.ready, {"ready": True, "pid": os.getpid(), "preissued_credentials": True})
    try:
        for code in args.profiles:
            for index in range(-args.warmups, args.samples):
                row = {"profile": code, "sample": index, "warmup": index < 0, "passed": False}
                try:
                    config, authority, credentials, certificate = prepared[code]
                    server = Server(config, credentials, certificate)
                    with listener.accept()[0] as connection:
                        connection.settimeout(args.timeout)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        row["local"], row["peer"] = connection.getsockname(), connection.getpeername()
                        deadline = deadline_for(args.timeout)
                        hello = recv_frame(connection, deadline)
                        first_ns = time.perf_counter_ns()
                        reply = server.receive_client_hello(hello)
                        flight = server.send_authenticated_flight()
                        payloads = [reply] + [record for _, record, _ in flight]
                        outbound = b"".join(frame(payload) for payload in payloads)
                        connection.sendall(outbound)
                        finished = recv_frame(connection, deadline)
                        server.receive_client_finished(finished)
                        row["server_handshake_ns"] = time.perf_counter_ns() - first_ns
                        application = recv_frame(connection, deadline)
                        content_type, payload = server.application_client_records.open(application, app_type)
                        if content_type != app_type or payload != b"kernel-network-request":
                            raise ValueError("authenticated application request differs")
                        exporter = server.exporter_secret("kernel-network-evidence", b"context")
                        response = server.application_server_records.seal(app_type, b"kernel-network-response:" + exporter)
                        connection.sendall(frame(response))
                        incoming = frame(hello) + frame(finished) + frame(application)
                        outgoing = outbound + frame(response)
                        row.update({"passed": True, "incoming_tcp_payload_bytes": len(incoming),
                            "outgoing_tcp_payload_bytes": len(outgoing), "incoming_sha256": hashlib.sha256(incoming).hexdigest(),
                            "outgoing_sha256": hashlib.sha256(outgoing).hexdigest(),
                            "server_flight_tcp_payload_bytes": len(outbound), "server_flight_bare_bytes": sum(map(len, payloads)),
                            "server_flight_record_lengths": list(map(len, payloads)),
                            "handshake_tcp_payload_bytes": len(frame(hello)) + len(outbound) + len(frame(finished)),
                            "handshake_bare_bytes": len(hello) + sum(map(len, payloads)) + len(finished),
                            "record_count_handshake": len(payloads) + 2})
                    append_json(args.result, row)
                except BaseException as error:
                    row["error"] = type(error).__name__ + ": " + str(error)
                    append_json(args.result, row)
                    raise
    finally:
        listener.close()


def client_worker(args):
    x509, profiles, Authority, _, Client, _, app_type, recv_frame, deadline_for = imports()
    configs = profiles(args.fixtures, handshake_signer=args.handshake_signer)
    prepared = {}
    for code in args.profiles:
        config = configs[code]
        metadata = json.loads((Path(config.alt_fixture) / "fixture.json").read_text())
        kind = "alt" if config.alt_chain else ("hybrid" if config.pq_enabled else "classical")
        root = x509.load_der_x509_certificate((Path(config.alt_fixture) / metadata["chains"][kind]["root"]).read_bytes())
        prepared[code] = (config, Authority(config.classical()), root)
    for code in args.profiles:
        for index in range(-args.warmups, args.samples):
            row = {"profile": code, "sample": index, "warmup": index < 0, "passed": False}
            try:
                config, authority, root = prepared[code]
                require_quiet(args.workload_owner_pid)
                client = Client(config, authority, trusted_root=root, trusted_name="server.example")
                # Ephemeral key/ClientHello preparation and TCP establishment
                # are separately excluded from the authentication interval.
                preparation = time.perf_counter_ns()
                hello = client.create_client_hello()
                row["client_hello_prepare_ns"] = time.perf_counter_ns() - preparation
                connected = time.perf_counter_ns()
                with socket.create_connection((args.address, args.port), args.timeout) as connection:
                    row["tcp_connect_ns"] = time.perf_counter_ns() - connected
                    connection.settimeout(args.timeout)
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    row["local"], row["peer"] = connection.getsockname(), connection.getpeername()
                    deadline = deadline_for(args.timeout)
                    started = time.perf_counter_ns()
                    connection.sendall(frame(hello))
                    reply = recv_frame(connection, deadline)
                    client.receive_server_hello(reply)
                    flight = [reply]
                    while not client.server_flight_complete:
                        record = recv_frame(connection, deadline)
                        flight.append(record)
                        client.receive_server_record(record)
                    client.finish_server_flight()
                    row["authenticated_ns"] = time.perf_counter_ns() - started
                    verified = client.alt_chain_verification
                    row["alt_chain_checked_edges"] = verified.checked_edges
                    row["alt_chain_legacy_edges"] = verified.legacy_edges
                    row["alt_chain_verifiers"] = list(verified.verifiers)
                    if config.alt_chain and (verified.checked_edges != 2 or verified.legacy_edges != 0):
                        raise ValueError("required alternative chain did not verify both edges")
                    if code in ("P2", "P3") and any(x.get("mode") != "native" or
                            x.get("library_sha256") != os.environ["A15_KERNEL_LIBRARY_SHA256"] for x in verified.verifiers):
                        raise ValueError("network timing requires the exact native SLH verifier, no Python fallback")
                    finished = client.send_client_finished()
                    application = client.application_client_records.seal(app_type, b"kernel-network-request")
                    connection.sendall(frame(finished) + frame(application))
                    response = recv_frame(connection, deadline)
                    content_type, payload = client.application_server_records.open(response, app_type)
                    exporter = client.exporter_secret("kernel-network-evidence", b"context")
                    if content_type != app_type or payload != b"kernel-network-response:" + exporter:
                        raise ValueError("application response/exporter mismatch")
                    row["application_confirmed_ns"] = time.perf_counter_ns() - started
                    outgoing = frame(hello) + frame(finished) + frame(application)
                    incoming = b"".join(frame(payload) for payload in flight) + frame(response)
                    row.update({"passed": True, "incoming_tcp_payload_bytes": len(incoming),
                        "outgoing_tcp_payload_bytes": len(outgoing), "incoming_sha256": hashlib.sha256(incoming).hexdigest(),
                        "outgoing_sha256": hashlib.sha256(outgoing).hexdigest(),
                        "server_flight_tcp_payload_bytes": sum(4 + len(x) for x in flight),
                        "server_flight_bare_bytes": sum(map(len, flight)),
                        "server_flight_record_lengths": list(map(len, flight)),
                        "handshake_tcp_payload_bytes": len(frame(hello)) + sum(4 + len(x) for x in flight) + len(frame(finished)),
                        "handshake_bare_bytes": len(hello) + sum(map(len, flight)) + len(finished),
                        "record_count_handshake": len(flight) + 2,
                        "protocol_server_flights": 1, "application_and_exporter_verified": True})
                row["authentication_succeeded"] = True
                require_quiet(args.workload_owner_pid)
                row["timing_accepted"] = True
                append_json(args.result, row)
            except BaseException as error:
                row["passed"] = False
                row["timing_accepted"] = False
                row["error"] = type(error).__name__ + ": " + str(error)
                append_json(args.result, row)
                raise


def capture_worker(args):
    # Linux SO_TIMESTAMPNS supplies kernel timestamps, not Python recv time.
    timestamp_ns = getattr(socket, "SO_TIMESTAMPNS", 35)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind((args.interface, 0))
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    raw.setsockopt(socket.SOL_SOCKET, timestamp_ns, 1)
    raw.settimeout(0.1)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *unused: stopped.set())
    packets, kernel_timestamps, idle_after_stop = 0, 0, 0
    with Path(args.pcap).open("xb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        write_json(args.ready, {"ready": True, "interface": args.interface, "kernel_timestamps": True})
        try:
            while not stopped.is_set() or idle_after_stop < 3:
                try:
                    payload, ancillary, _, address = raw.recvmsg(65535, 128)
                except socket.timeout:
                    if stopped.is_set():
                        idle_after_stop += 1
                    continue
                idle_after_stop = 0
                stamp = None
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == timestamp_ns:
                        seconds, nanoseconds = struct.unpack("@ll", value[:16])
                        stamp = seconds * 1_000_000_000 + nanoseconds
                        kernel_timestamps += 1
                if stamp is None:
                    raise RuntimeError("AF_PACKET capture lacks kernel timestamps")
                stream.write(struct.pack("<IIII", stamp // 1_000_000_000, stamp % 1_000_000_000, len(payload), len(payload)))
                stream.write(payload)
                packets += 1
        finally:
            # PACKET_STATISTICS resets counters when read; read exactly once.
            statistics_raw = raw.getsockopt(263, 6, 8)
            received, dropped = struct.unpack("II", statistics_raw)
            raw.close()
            stream.flush()
            os.fsync(stream.fileno())
            write_json(args.result, {"packets_written": packets, "kernel_timestamps": kernel_timestamps,
                "socket_packets_received": received, "socket_packets_dropped": dropped,
                "pcap_sha256": sha(args.pcap), "timestamp_source": "Linux SO_TIMESTAMPNS"})


def parse_pcap(path):
    packets = []
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if header[:4] != bytes.fromhex("4d3cb2a1"):
            raise ValueError("expected nanosecond little-endian Ethernet pcap")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("truncated pcap packet header")
            seconds, nanos, size, original = struct.unpack("<IIII", record)
            data = stream.read(size)
            if len(data) != size or original != size:
                raise ValueError("truncated pcap frame")
            if len(data) < 54 or data[12:14] != b"\x08\x00":
                continue
            ip = data[14:]
            ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
            if ip[9] != 6:
                continue
            if total > 1500 or len(ip) < total or int.from_bytes(ip[6:8], "big") & 0x3fff:
                raise ValueError("fragmented/oversized TCP capture; offload exclusion failed")
            tcp = ip[ihl:total]
            offset = (tcp[12] >> 4) * 4
            if offset < 20 or offset > len(tcp):
                raise ValueError("invalid TCP data offset")
            src_port, dst_port, seq, ack = struct.unpack("!HHII", tcp[:12])
            packets.append({"timestamp_ns": seconds * 1_000_000_000 + nanos,
                "source": socket.inet_ntoa(ip[12:16]), "destination": socket.inet_ntoa(ip[16:20]),
                "source_port": src_port, "destination_port": dst_port,
                "sequence": seq, "acknowledgment": ack, "flags": tcp[13], "payload": tcp[offset:],
                "ip_bytes": total, "ethernet_bytes": len(data), "tcp_header_bytes": offset})
    return packets


def assembled_stream(packets, expected_bytes):
    if not isinstance(expected_bytes, int) or not 0 <= expected_bytes <= (1 << 20):
        raise ValueError("expected captured TCP stream exceeds the evidence bound")
    syn = [x for x in packets if x["flags"] & 2]
    if not syn:
        raise ValueError("capture lacks TCP SYN")
    origin = (syn[0]["sequence"] + 1) & 0xffffffff
    payload, seen = bytearray(expected_bytes), bytearray(expected_bytes)
    retransmitted = 0
    for packet in packets:
        if not packet["payload"]:
            continue
        offset = (packet["sequence"] - origin) & 0xffffffff
        if offset + len(packet["payload"]) > expected_bytes:
            raise ValueError("TCP sequence leaves the bounded endpoint stream; wrong connection or malformed capture")
        for index, value in enumerate(packet["payload"], offset):
            if seen[index]:
                if payload[index] != value:
                    raise ValueError("inconsistent retransmitted TCP payload")
                retransmitted += 1
            payload[index] = value
            seen[index] = 1
    if not all(seen):
        raise ValueError("TCP capture has a payload gap")
    return bytes(payload), retransmitted


def analyse_capture(path, client_rows, server_rows, *, server_observation=False):
    packets = parse_pcap(path)
    # Linux may reuse an ephemeral port during one campaign. A new client SYN
    # with a different initial sequence starts another connection, even when
    # its four-tuple matches an earlier one. Never combine those sequence spaces.
    connections, active = {}, {}
    server_port = server_rows[0]["local"][1] if server_rows else None
    server_address = server_rows[0]["local"][0] if server_rows else None
    for packet in packets:
        outbound = packet["destination_port"] == server_port and packet["destination"] == server_address
        inbound = packet["source_port"] == server_port and packet["source"] == server_address
        if not outbound and not inbound:
            continue
        key = (packet["source"] if outbound else packet["destination"],
               packet["source_port"] if outbound else packet["destination_port"])
        if outbound and packet["flags"] & 2 and not packet["flags"] & 16:
            if key not in active or active[key]["syn_sequence"] != packet["sequence"]:
                connection = {"syn_sequence": packet["sequence"], "packets": []}
                connections.setdefault(key, []).append(connection)
                active[key] = connection
        if key not in active:
            raise ValueError("TCP capture starts after a connection SYN")
        active[key]["packets"].append(packet)
    consumed = {}
    results = []
    for client, server in zip(client_rows, server_rows):
        if (client["profile"], client["sample"]) != (server["profile"], server["sample"]) or not client["passed"] or not server["passed"]:
            raise ValueError("client/server trial identity or status differs")
        key = tuple(client["local"])
        index = consumed.get(key, 0)
        if index >= len(connections.get(key, [])):
            raise ValueError("capture lacks the matching client connection instance")
        selected = connections[key][index]["packets"]
        consumed[key] = index + 1
        incoming = [p for p in selected if p["source_port"] == server["local"][1]]
        outgoing = [p for p in selected if p["destination_port"] == server["local"][1]]
        server_data, server_repeated = assembled_stream(incoming, client["incoming_tcp_payload_bytes"])
        client_data, client_repeated = assembled_stream(outgoing, client["outgoing_tcp_payload_bytes"])
        if (len(server_data) != client["incoming_tcp_payload_bytes"] or
                len(client_data) != client["outgoing_tcp_payload_bytes"] or
                hashlib.sha256(server_data).hexdigest() != client["incoming_sha256"] or
                hashlib.sha256(client_data).hexdigest() != client["outgoing_sha256"] or
                client["incoming_sha256"] != server["outgoing_sha256"] or
                client["outgoing_sha256"] != server["incoming_sha256"]):
            raise ValueError("captured TCP bytes differ from authenticated endpoint streams")
        for field in ("server_flight_tcp_payload_bytes", "server_flight_bare_bytes", "server_flight_record_lengths",
                      "handshake_tcp_payload_bytes", "handshake_bare_bytes", "record_count_handshake"):
            if client[field] != server[field]:
                raise ValueError("endpoint handshake byte accounting differs: " + field)
        if client["handshake_tcp_payload_bytes"] != client["handshake_bare_bytes"] + 4 * client["record_count_handshake"]:
            raise ValueError("TCP framing overhead does not match record count")
        if not any(p["flags"] & 1 for p in incoming) or not any(p["flags"] & 1 for p in outgoing):
            raise ValueError("capture stopped before both TCP FIN tails")
        fin_acks = []
        for direction, reverse in ((incoming, outgoing), (outgoing, incoming)):
            fin = next(p for p in direction if p["flags"] & 1)
            required = (fin["sequence"] + len(fin["payload"]) + 1) & 0xffffffff
            fin_acks.append(any(p["flags"] & 16 and p["acknowledgment"] == required for p in reverse))
        if not all(fin_acks):
            raise ValueError("capture stopped before acknowledgment of both FIN tails")
        row = {"profile": client["profile"], "sample": client["sample"], "warmup": client["warmup"], "passed": True,
            "tcp_packets": len(selected), "pure_ack_packets": sum(bool(p["flags"] & 16) and not p["payload"] and not p["flags"] & 7 for p in selected),
            "payload_segments_server": sum(bool(p["payload"]) for p in incoming),
            "payload_segments_client": sum(bool(p["payload"]) for p in outgoing),
            "maximum_tcp_payload_segment": max(len(p["payload"]) for p in selected),
            "ip_bytes_total": sum(p["ip_bytes"] for p in selected),
            "ethernet_capture_bytes_total": sum(p["ethernet_bytes"] for p in selected),
            "retransmitted_payload_bytes": server_repeated + client_repeated,
            "client_tcp_payload_unique_bytes": len(client_data), "server_tcp_payload_unique_bytes": len(server_data),
            "server_flight_tcp_payload_bytes": client["server_flight_tcp_payload_bytes"],
            "handshake_tcp_payload_bytes": client["handshake_tcp_payload_bytes"],
            "handshake_bare_bytes": client["handshake_bare_bytes"], "authenticated_ns": client["authenticated_ns"],
            "tcp_connect_ns": client["tcp_connect_ns"], "application_confirmed_ns": client["application_confirmed_ns"],
            "capture_start_ns": min(p["timestamp_ns"] for p in selected), "capture_end_ns": max(p["timestamp_ns"] for p in selected),
            "fin_both_directions": True, "fin_ack_both_directions": True, "endpoint_and_capture_payloads_equal": True}
        if server_observation:
            payloads = [p for p in incoming if p["payload"]]
            origin = payloads[0]["sequence"]
            acknowledgment = next(p for p in outgoing if p["flags"] & 16 and
                                   0 < ((p["acknowledgment"] - origin) & 0xffffffff) < (1 << 31))
            flight_size = client["server_flight_tcp_payload_bytes"]
            flight_packets = [p for p in payloads if ((p["sequence"] - origin) & 0xffffffff) < flight_size]
            burst = [p for p in flight_packets if p["timestamp_ns"] < acknowledgment["timestamp_ns"]]
            row.update({"server_segments_before_first_data_ack": len(burst),
                        "server_payload_bytes_before_first_data_ack": sum(min(len(p["payload"]), flight_size - ((p["sequence"] - origin) & 0xffffffff)) for p in burst),
                        "server_flight_payload_segments": len(flight_packets),
                        "server_first_data_to_ack_ns": acknowledgment["timestamp_ns"] - payloads[0]["timestamp_ns"],
                        "configured_initcwnd_segments": 10})
        results.append(row)
    return results


def wait_ready(path, process, timeout):
    deadline = time.monotonic() + timeout
    while not Path(path).is_file():
        if process.poll() is not None:
            raise RuntimeError("worker exited before ready signal: " + str(process.returncode))
        if time.monotonic() >= deadline:
            raise TimeoutError("worker readiness deadline")
        # Orchestration polling only: never used to emulate link latency.
        time.sleep(0.02)


def _experiment(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {"schema": "a15-kernel-network-evidence-v1", "passed": False,
        "created_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
        "profiles": args.profiles, "samples_per_profile_per_rtt": args.samples, "warmups_per_profile_per_rtt": args.warmups,
        "configured_rtt_ms": args.rtts, "initcwnd_segments": 10,
        "library": str(args.library.resolve()), "library_sha256_before": sha(args.library),
        "fixture_sha256_before": tree_hashes(args.fixtures), "source_sha256_before": source_hashes(),
        "commands": [], "trials": [], "user_space_delay_substitution": False,
        "workload_guard": args.workload_guard,
        "scope": "Real Linux TCP/netns/veth/netem on one WSL host; private TLS harness with four-byte record prefixes; no standard TLS interoperability or physical-network claim",
        "timing_scope": "ClientHello send through authenticated server Finished; excludes imports, fixture loading, credential generation, ClientHello preparation and TCP connect; includes network/kernel, server cryptography and client verification",
        "capture_scope": "Both veth endpoint AF_PACKET Ethernet pcaps with Linux kernel timestamps, offloads disabled; totals include SYN/ACK/FIN and application confirmation; bare and framed handshake bytes separately recorded; FCS/preamble/physical link overhead excluded",
        "ca_12824_signing_calls": 0, "formal_performance_samples": 0,
        "host_load_before": os.getloadavg(), "cpu_affinity": sorted(os.sched_getaffinity(0))}
    processes = []
    logs = []
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE"):
        env.pop(key, None)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1",
                "A15_NATIVE_LIBRARY": str(args.library.resolve()), "SLHDSA_SM3_LIB": str(args.library.resolve()),
                "A15_KERNEL_LIBRARY_SHA256": record["library_sha256_before"]})
    script = Path(__file__).resolve()
    def start(namespace, action, folder, extra):
        log = (folder / (action + ".log")).open("xb")
        logs.append(log)
        argv = ["ip", "netns", "exec", namespace, sys.executable, "-B", str(script), action, *extra]
        process = subprocess.Popen([str(x) for x in argv], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        record["commands"].append({"argv": [str(x) for x in argv], "pid": process.pid})
        return process
    try:
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise RuntimeError("kernel network evidence requires Linux root")
        build_path = (args.build_record or args.library.resolve().parent / "build-record.json").resolve()
        build = json.loads(build_path.read_text(encoding="utf-8"))
        if build.get("schema") != "a15-cpu-build-v1" or build.get("compile_output_checked") is not True or build.get("library_sha256") != record["library_sha256_before"]:
            raise ValueError("native library lacks a matching checked CPU build record")
        compiled = build.get("source_sha256")
        if not isinstance(compiled, dict) or not compiled:
            raise ValueError("native build record lacks source identities")
        for name, expected in compiled.items():
            path = (ROOT / name).resolve()
            if not path.is_relative_to(ROOT) or not path.is_file() or sha(path) != expected:
                raise ValueError("compiled source differs from native build record: " + name)
        record["build_record"] = str(build_path)
        record["build_record_sha256_before"] = sha(build_path)
        record["compiled_source_sha256"] = compiled
        metadata = [json.loads((args.fixtures / name / "fixture.json").read_text()) for name in
                    ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44")]
        if any(not x.get("test_only") or x["handshake_signer"] != args.handshake_signer for x in metadata):
            raise ValueError("fixtures must be preissued test-only credentials with matching signer")
        write_json(output / "run-plan.json", {**record, "status": "started"})
        with IsolatedLink(record["commands"], rtt_ms=args.rtts[0]) as link:
            for rtt in args.rtts:
                link.delay(rtt)
                folder = output / ("rtt-" + str(rtt))
                folder.mkdir()
                # Record actual qdisc/offload/route configuration, not only argv.
                for interface, namespace in zip(link.interfaces, link.names):
                    link.ns(namespace, "tc", "-s", "qdisc", "show", "dev", interface)
                    link.ns(namespace, "ethtool", "-k", interface)
                    link.ns(namespace, "ip", "route", "show")
                    link.ns(namespace, "sysctl", "net.ipv4.tcp_congestion_control", "net.ipv4.tcp_timestamps")
                ping = link.ns(link.client, "ping", "-n", "-c", "3", "-i", "0.2", "-W", "2", link.server_address)
                (folder / "ping.txt").write_text(ping["stdout"], encoding="utf-8")
                captures = []
                for direction, interface, namespace in zip(("client", "server"), link.interfaces, link.names):
                    capture_folder = folder / direction
                    capture_folder.mkdir()
                    capture = start(namespace, "capture", capture_folder, ["--interface", interface,
                        "--pcap", capture_folder / "capture.pcap", "--ready", capture_folder / "ready.json",
                        "--result", capture_folder / "capture.json"])
                    wait_ready(capture_folder / "ready.json", capture, args.timeout)
                    captures.append(capture)
                common = ["--fixtures", args.fixtures.resolve(), "--handshake-signer", args.handshake_signer,
                          "--workload-owner-pid", str(args.workload_owner_pid),
                          "--profiles", *args.profiles, "--samples", args.samples, "--warmups", args.warmups, "--timeout", args.timeout,
                          "--address", link.server_address, "--port", "4443"]
                server = start(link.server, "server", folder, [*common, "--result", folder / "server.jsonl", "--ready", folder / "server-ready.json"])
                wait_ready(folder / "server-ready.json", server, args.timeout)
                client = start(link.client, "client", folder, [*common, "--result", folder / "client.jsonl"])
                limit = args.timeout * (args.samples + args.warmups) * len(args.profiles) + 30
                if client.wait(timeout=limit) or server.wait(timeout=limit):
                    raise RuntimeError("client/server handshake worker failed; preserve logs")
                for capture in captures:
                    capture.send_signal(signal.SIGTERM)
                for capture in captures:
                    if capture.wait(timeout=10):
                        raise RuntimeError("packet capture worker failed")
                clients = [json.loads(line) for line in (folder / "client.jsonl").read_text().splitlines()]
                servers = [json.loads(line) for line in (folder / "server.jsonl").read_text().splitlines()]
                if len(clients) != (args.samples + args.warmups) * len(args.profiles) or len(servers) != len(clients):
                    raise ValueError("missing trial endpoint rows")
                results = None
                for direction in ("client", "server"):
                    capture_folder = folder / direction
                    stats = json.loads((capture_folder / "capture.json").read_text())
                    if stats["socket_packets_dropped"] or stats["kernel_timestamps"] != stats["packets_written"]:
                        raise ValueError("capture dropped packets or lacks kernel timestamps")
                    analysed = analyse_capture(capture_folder / "capture.pcap", clients, servers, server_observation=direction == "server")
                    write_json(capture_folder / "analysis.json", analysed)
                    if direction == "server":
                        results = analysed
                for trial in results:
                    trial["configured_rtt_ms"] = rtt
                record["trials"].extend(results)
                print(json.dumps({"rtt_ms": rtt, "passed_trials": len(results)}), flush=True)
            record["passed"] = len(record["trials"]) == len(args.rtts) * len(args.profiles) * (args.samples + args.warmups)
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        for log in logs:
            log.close()
        record["source_sha256_after"] = source_hashes()
        record["library_sha256_after"] = sha(args.library)
        record["fixture_sha256_after"] = tree_hashes(args.fixtures)
        record["source_unchanged"] = record["source_sha256_before"] == record["source_sha256_after"]
        record["library_unchanged"] = record["library_sha256_before"] == record["library_sha256_after"]
        record["fixtures_unchanged"] = record["fixture_sha256_before"] == record["fixture_sha256_after"]
        record["host_load_after"] = os.getloadavg()
        if "build_record" in record:
            record["build_record_sha256_after"] = sha(Path(record["build_record"]))
            record["build_record_unchanged"] = record["build_record_sha256_before"] == record["build_record_sha256_after"]
            record["passed"] = record["passed"] and record["build_record_unchanged"]
        record["passed"] = record["passed"] and all(record[x] for x in ("source_unchanged", "library_unchanged", "fixtures_unchanged"))
        summary = []
        for rtt in args.rtts:
            for code in args.profiles:
                rows = [r for r in record["trials"] if r["configured_rtt_ms"] == rtt and r["profile"] == code and not r["warmup"]]
                if rows:
                    values = [r["authenticated_ns"] / 1e6 for r in rows]
                    quartiles = statistics.quantiles(values, n=4, method="inclusive") if len(values) > 1 else [values[0]] * 3
                    summary.append({"profile": code, "configured_rtt_ms": rtt, "samples": len(values),
                        "authenticated_ms_median": statistics.median(values), "authenticated_ms_iqr": quartiles[2] - quartiles[0],
                        "authenticated_ms_min": min(values), "authenticated_ms_max": max(values),
                        "server_flight_tcp_payload_bytes_range": [min(r["server_flight_tcp_payload_bytes"] for r in rows), max(r["server_flight_tcp_payload_bytes"] for r in rows)],
                        "tcp_segments_server_range": [min(r["payload_segments_server"] for r in rows), max(r["payload_segments_server"] for r in rows)],
                        "server_flight_segments_range": [min(r["server_flight_payload_segments"] for r in rows), max(r["server_flight_payload_segments"] for r in rows)],
                        "server_first_burst_segments_range": [min(r["server_segments_before_first_data_ack"] for r in rows), max(r["server_segments_before_first_data_ack"] for r in rows)]})
        record["summary"] = summary
        record["artifact_sha256"] = {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}
        write_json(output / "manifest.json", record)
    print(json.dumps({"passed": record["passed"], "trials": len(record["trials"]), "error": record.get("error"), "output": str(output)}), flush=True)
    return 0 if record["passed"] else 1


def experiment(args):
    with performance_exclusive(ROOT, "kernel-network") as guard:
        args.workload_guard = guard
        args.workload_owner_pid = os.getpid()
        return _experiment(args)


def probe(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {"schema": "a15-kernel-network-probe-v1", "passed": False,
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "euid": os.geteuid() if hasattr(os, "geteuid") else None,
              "script_sha256": sha(__file__), "commands": [], "user_space_delay_substitution": False}
    try:
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise RuntimeError("kernel network evidence requires Linux root/CAP_NET_ADMIN and CAP_NET_RAW")
        with IsolatedLink(record["commands"]) as link:
            for interface, namespace in zip(link.interfaces, link.names):
                link.ns(namespace, "tc", "-s", "qdisc", "show", "dev", interface)
            record["passed"] = True
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    record["source_unchanged"] = record["script_sha256"] == sha(__file__)
    with (output / "probe.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"passed": record["passed"], "output": str(output), "error": record.get("error")}), flush=True)
    return 0 if record["passed"] and record["source_unchanged"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "run", "server", "client", "capture"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--workload-owner-pid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--handshake-signer", default="falcon-512")
    parser.add_argument("--profiles", nargs="+", choices=("P0", "P1", "P2", "P3", "P4"), default=["P0", "P1", "P2", "P3", "P4"])
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--rtts", nargs="+", type=int, default=[20, 100])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--address")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--interface")
    parser.add_argument("--pcap", type=Path)
    args = parser.parse_args()
    if args.samples < 1 or args.warmups < 0 or args.timeout < 1 or any(x < 1 for x in args.rtts) or len(set(args.profiles)) != len(args.profiles) or len(set(args.rtts)) != len(args.rtts):
        parser.error("samples/timeouts/RTTs must be positive; profiles/RTTs must be unique")
    if args.action in ("probe", "run") and args.output is None:
        parser.error("--output is required")
    if args.action in ("run", "client", "server") and args.fixtures is None:
        parser.error("--fixtures is required")
    if args.action == "run":
        if args.library is None:
            parser.error("--library is required")
        return experiment(args)
    if args.action == "server":
        server_worker(args)
        return 0
    if args.action == "client":
        client_worker(args)
        return 0
    if args.action == "capture":
        capture_worker(args)
        return 0
    return probe(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
