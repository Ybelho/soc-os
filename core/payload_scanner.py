import json
import os
import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    allowed = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    out: List[str] = []
    buf = bytearray()
    for b in data:
        if b in allowed:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                try:
                    out.append(buf.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            buf.clear()
    if len(buf) >= min_len:
        try:
            out.append(buf.decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return out


def _extract_utf16le_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    buf = bytearray()
    i = 0
    while i + 1 < len(data):
        ch = data[i]
        nul = data[i + 1]
        if nul == 0x00 and 0x20 <= ch <= 0x7E:
            buf.extend([ch, nul])
            i += 2
        else:
            if len(buf) >= min_len * 2:
                try:
                    out.append(buf.decode("utf-16le", errors="ignore"))
                except Exception:
                    pass
            buf.clear()
            i += 2
    if len(buf) >= min_len * 2:
        try:
            out.append(buf.decode("utf-16le", errors="ignore"))
        except Exception:
            pass
    return out


def _snip_context(s: str, start: int, end: int, pad: int = 140) -> str:
    a = max(0, start - pad)
    b = min(len(s), end + pad)
    return s[a:b].replace("\r", "\\r")


@dataclass
class FlowMeta:
    proto: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    stream_id: Optional[int]
    first_ts: float


class FlowStore:
    """
    Bounded in-memory store (LRU eviction).
    """
    def __init__(self, max_bytes_per_flow: int = 1_000_000, max_total_bytes: int = 200_000_000):
        self.max_bytes_per_flow = max_bytes_per_flow
        self.max_total_bytes = max_total_bytes
        self.total_bytes = 0
        self.buffers: "OrderedDict[str, bytearray]" = OrderedDict()
        self.meta: Dict[str, FlowMeta] = {}

    def _evict_if_needed(self):
        while self.total_bytes > self.max_total_bytes and self.buffers:
            k, buf = self.buffers.popitem(last=False)
            self.total_bytes -= len(buf)
            self.meta.pop(k, None)

    def append(self, key: str, meta: FlowMeta, chunk: bytes):
        if not chunk:
            return

        if key not in self.buffers:
            self.buffers[key] = bytearray()
            self.meta[key] = meta
        else:
            self.buffers.move_to_end(key, last=True)

        buf = self.buffers[key]
        remaining = self.max_bytes_per_flow - len(buf)
        if remaining <= 0:
            return

        to_add = chunk[:remaining]
        buf.extend(to_add)
        self.total_bytes += len(to_add)
        self._evict_if_needed()


class PayloadScanner:
    """
    Payload scanner: cherche des patterns "command-like" dans payloads TCP/UDP.
    Ne promet pas de déchiffrement TLS; sert surtout sur trafic clair.
    """

    DEFAULT_PATTERNS: List[Tuple[str, str]] = [
        ("wget", r"(?i)\bwget\b[^\n\r;]{0,500}"),
        ("curl", r"(?i)\bcurl\b[^\n\r;]{0,500}"),
        ("powershell", r"(?i)\bpowershell(?:\.exe)?\b[^\n\r]{0,800}"),
        ("cmd", r"(?i)\bcmd(?:\.exe)?\b[^\n\r]{0,400}"),
        ("bash_sh", r"(?i)\b(?:/bin/(?:sh|bash)|sh\s+-c|bash\s+-c)\b[^\n\r]{0,600}"),
        ("chmod_x", r"(?i)\bchmod\s+\+x\b[^\n\r]{0,250}"),
        ("execution_dot_slash", r"(?m)(?:^|\s)(\./[A-Za-z0-9._/-]{2,200})"),
        ("sh_dot_slash", r"(?i)\bsh\s+(\./[A-Za-z0-9._/-]{2,200})"),
        ("python_exec", r"(?i)\bpython(?:3)?\b[^\n\r]{0,500}"),
        ("perl_exec", r"(?i)\bperl\b[^\n\r]{0,500}"),
        ("nc", r"(?i)\b(?:nc|netcat)\b[^\n\r]{0,500}"),
        ("base64_pipe", r"(?i)\bbase64\b[^\n\r]{0,500}"),
        ("certutil", r"(?i)\bcertutil\b[^\n\r]{0,600}"),
        ("bitsadmin", r"(?i)\bbitsadmin\b[^\n\r]{0,600}"),
    ]

    @staticmethod
    def _pick_ip(ip4: str, ip6: str) -> Optional[str]:
        ip4 = (ip4 or "").strip()
        ip6 = (ip6 or "").strip()
        return ip4 if ip4 else (ip6 if ip6 else None)

    @staticmethod
    def _hex_to_bytes(hex_s: str) -> bytes:
        if not hex_s:
            return b""
        hex_s = hex_s.replace(":", "").strip()
        if not hex_s:
            return b""
        try:
            return bytes.fromhex(hex_s)
        except Exception:
            return b""

    @staticmethod
    def _flow_key(proto: str,
                  tcp_stream: Optional[int],
                  src_ip: str, src_port: Optional[int],
                  dst_ip: str, dst_port: Optional[int]) -> str:
        if proto == "tcp" and tcp_stream is not None:
            return f"tcp_stream:{tcp_stream}"
        a = (src_ip, src_port, dst_ip, dst_port)
        b = (dst_ip, dst_port, src_ip, src_port)
        canon = a if str(a) <= str(b) else b
        return f"udp_flow:{canon}"

    @staticmethod
    def _run_tshark_payload_dump(pcap_path: str) -> Iterable[str]:
        """
        TSV:
        ts, tcp.stream, ip.src, ipv6.src, tcp.srcport, udp.srcport, ip.dst, ipv6.dst, tcp.dstport, udp.dstport,
        tcp.payload, tcp.segment_data, tcp.reassembled.data, data, data.data, http.file_data, telnet.data, udp.payload
        """
        cmd = [
            "tshark", "-r", pcap_path,
            "-o", "tcp.desegment_tcp_streams:true",
            "-o", "tcp.reassemble_out_of_order:true",
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "tcp.stream",
            "-e", "ip.src", "-e", "ipv6.src",
            "-e", "tcp.srcport", "-e", "udp.srcport",
            "-e", "ip.dst", "-e", "ipv6.dst",
            "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "tcp.payload",
            "-e", "tcp.segment_data",
            "-e", "tcp.reassembled.data",
            "-e", "data",
            "-e", "data.data",
            "-e", "http.file_data",
            "-e", "telnet.data",
            "-e", "udp.payload",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n")
        proc.wait()

    @staticmethod
    def scan_to_jsonl(
        pcap_path: str,
        output_jsonl: str,
        patterns: Optional[List[Tuple[str, str]]] = None,
        min_string_len: int = 4,
        max_hits: int = 5000,
        max_bytes_per_flow: int = 1_000_000,
        max_total_bytes: int = 200_000_000,
    ) -> str:
        pats = patterns or PayloadScanner.DEFAULT_PATTERNS
        compiled = [(name, re.compile(rx)) for name, rx in pats]

        store = FlowStore(max_bytes_per_flow=max_bytes_per_flow, max_total_bytes=max_total_bytes)

        for line in PayloadScanner._run_tshark_payload_dump(pcap_path):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 18:
                continue

            ts_s = parts[0]
            tcp_stream_s = parts[1]
            ip_src4, ip_src6 = parts[2], parts[3]
            tcp_sp, udp_sp = parts[4], parts[5]
            ip_dst4, ip_dst6 = parts[6], parts[7]
            tcp_dp, udp_dp = parts[8], parts[9]

            tcp_payload = parts[10]
            tcp_seg = parts[11]
            tcp_reass = parts[12]
            data_f = parts[13]
            data_data = parts[14]
            http_file = parts[15]
            telnet_data = parts[16]
            udp_payload = parts[17]

            try:
                ts = float(ts_s) if ts_s else 0.0
            except Exception:
                ts = 0.0

            src_ip = PayloadScanner._pick_ip(ip_src4, ip_src6)
            dst_ip = PayloadScanner._pick_ip(ip_dst4, ip_dst6)
            if not src_ip or not dst_ip:
                continue

            tcp_stream = int(tcp_stream_s) if tcp_stream_s.strip() else None

            proto = None
            src_port = None
            dst_port = None
            blobs: List[bytes] = []

            tcp_any = any(x and x.strip() for x in [
                tcp_payload, tcp_seg, tcp_reass, data_f, data_data, http_file, telnet_data
            ])

            if tcp_any:
                proto = "tcp"
                src_port = int(tcp_sp) if tcp_sp.strip() else None
                dst_port = int(tcp_dp) if tcp_dp.strip() else None

                for x in [tcp_reass, tcp_payload, tcp_seg, http_file, telnet_data, data_data, data_f]:
                    if x and x.strip():
                        blobs.append(PayloadScanner._hex_to_bytes(x))

            elif udp_payload and udp_payload.strip():
                proto = "udp"
                src_port = int(udp_sp) if udp_sp.strip() else None
                dst_port = int(udp_dp) if udp_dp.strip() else None
                blobs.append(PayloadScanner._hex_to_bytes(udp_payload))
            else:
                continue

            payload_bytes = b"".join(b for b in blobs if b)
            if not payload_bytes:
                continue

            key = PayloadScanner._flow_key(proto, tcp_stream, src_ip, src_port, dst_ip, dst_port)
            meta = FlowMeta(
                proto=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=tcp_stream if proto == "tcp" else None,
                first_ts=ts,
            )

            store.append(key, meta, payload_bytes + b"\n")

        hits = 0
        os.makedirs(os.path.dirname(output_jsonl) or ".", exist_ok=True)

        # de-dup simple
        seen = set()

        with open(output_jsonl, "w", encoding="utf-8") as f_out:
            for key, buf in store.buffers.items():
                meta = store.meta.get(key)
                if not meta:
                    continue
                data = bytes(buf)

                strings: List[str] = []
                strings.extend(_extract_ascii_strings(data, min_len=min_string_len))
                strings.extend(_extract_utf16le_strings(data, min_len=min_string_len))
                if not strings:
                    continue

                for s in strings:
                    s_low = s.lower()
                    token_hit = any(t in s_low for t in [
                        "wget", "curl", "powershell", "cmd", "chmod", "./", "/bin/", "sh -c", "bash -c"
                    ])
                    if (not token_hit) and len(s) > 3000:
                        continue

                    for name, creg in compiled:
                        for m in creg.finditer(s):
                            if hits >= max_hits:
                                return output_jsonl

                            start, end = m.start(), m.end()
                            matched = m.group(0)
                            ctx = _snip_context(s, start, end)

                            dedup_key = (key, name, matched[:120])
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)

                            confidence = "high" if ("http" in matched.lower() or "://" in matched) else "medium"
                            if len(matched.strip()) <= 6:
                                confidence = "low"

                            event = {
                                "timestamp": float(meta.first_ts),
                                "proto": meta.proto,
                                "src_ip": meta.src_ip,
                                "dst_ip": meta.dst_ip,
                                "src_port": meta.src_port,
                                "dst_port": meta.dst_port,
                                "stream_id": meta.stream_id,
                                "pattern": name,
                                "confidence": confidence,
                                "match": matched[:900],
                                "context": ctx[:2500],
                                "flow_key": key,
                            }
                            f_out.write(json.dumps(event, ensure_ascii=False) + "\n")
                            hits += 1

        return output_jsonl
