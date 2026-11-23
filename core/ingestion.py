import os
import shutil
import subprocess
from pathlib import Path
import json

# pip install python-evtx
from Evtx.Evtx import Evtx  
from Evtx.Views import evtx_file_xml_view

from core.payload_scanner import PayloadScanner
from core.file_triage import FileTriage

class PcapIngestor:
    """
    PCAP -> artifacts:
      - Zeek logs (json lines) : local si dispo, sinon Docker (zeek/zeek)
      - Suricata eve.json      : local si dispo, sinon Docker
      - Export objets HTTP     : tshark (best effort)
      - Payload scanner hits   : payload_hits.jsonl (best effort)
      - File triage (hashes)   : exported_files.jsonl (best effort)
      - EVTX logs              : evtx_jsonl (best effort)
    """

    @staticmethod
    def _run(cmd, cwd=None):
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\nSTDERR:\n{res.stderr[:2000]}"
            )
        return res

    @staticmethod
    def _run_docker(image: str, args: list, mounts: list, workdir: str = None):
        docker_bin = shutil.which("docker")
        if not docker_bin:
            raise RuntimeError("Docker introuvable. Installe Docker Desktop et active l’intégration WSL.")

        cmd = [docker_bin, "run", "--rm"]
        for host_p, cont_p, mode in mounts:
            cmd += ["-v", f"{host_p}:{cont_p}:{mode}"]
        if workdir:
            cmd += ["-w", workdir]
        cmd += [image] + args
        return PcapIngestor._run(cmd)

    @staticmethod
    def run_zeek(pcap_path: str, out_dir: str) -> tuple[dict, str]:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        zeek_bin = shutil.which("zeek")
        if zeek_bin:
            cmd = [zeek_bin, "-r", pcap_path, "-C", "LogAscii::use_json=T"]
            PcapIngestor._run(cmd, cwd=out_dir)
            mode = "local"
        else:
            pcap_abs = str(Path(pcap_path).resolve())
            out_abs = str(Path(out_dir).resolve())

            PcapIngestor._run_docker(
                image="zeek/zeek:latest",
                args=["zeek", "-r", "/pcap/capture.pcap", "-C", "LogAscii::use_json=T"],
                mounts=[
                    (out_abs, "/out", "rw"),
                    (pcap_abs, "/pcap/capture.pcap", "ro"),
                ],
                workdir="/out",
            )
            mode = "docker"

        logs = {}
        for p in Path(out_dir).glob("*.log"):
            logs[p.stem] = str(p)
        return logs, mode

    @staticmethod
    def run_suricata(pcap_path: str, out_dir: str) -> tuple[str, str]:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        suri_bin = shutil.which("suricata")
        if suri_bin:
            cmd = [suri_bin, "-r", pcap_path, "-l", out_dir]
            PcapIngestor._run(cmd)
            mode = "local"
        else:
            pcap_abs = str(Path(pcap_path).resolve())
            out_abs = str(Path(out_dir).resolve())
            PcapIngestor._run_docker(
                image="oisf/suricata:latest",
                args=["suricata", "-r", "/pcap/capture.pcap", "-l", "/out"],
                mounts=[
                    (out_abs, "/out", "rw"),
                    (pcap_abs, "/pcap/capture.pcap", "ro"),
                ],
                workdir="/out",
            )
            mode = "docker"

        eve = str(Path(out_dir) / "eve.json")
        if not os.path.exists(eve):
            raise RuntimeError("Suricata n'a pas généré eve.json (config suricata ou capture non compatible).")

        return eve, mode

    @staticmethod
    def export_http_objects(pcap_path: str, out_dir: str) -> str:
        tshark_bin = shutil.which("tshark")
        if not tshark_bin:
            raise RuntimeError("tshark introuvable dans le PATH.")

        Path(out_dir).mkdir(parents=True, exist_ok=True)
        cmd = [tshark_bin, "-r", pcap_path, "--export-objects", f"http,{out_dir}"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out_dir

    @staticmethod
    def run_payload_scanner(pcap_path: str, out_path_jsonl: str) -> str:
        tshark_bin = shutil.which("tshark")
        if not tshark_bin:
            raise RuntimeError("tshark introuvable dans le PATH (payload_scanner nécessite tshark).")

        return PayloadScanner.scan_to_jsonl(
            pcap_path=pcap_path,
            output_jsonl=out_path_jsonl,
            min_string_len=4,
            max_hits=5000,
            max_bytes_per_flow=1_000_000,
            max_total_bytes=200_000_000
        )

    @staticmethod
    def evtx_to_jsonl(evtx_path: str, jsonl_out: str):
        """Parse EVTX binaire vers JSONL"""
        try:
            with open(jsonl_out, "w", encoding="utf-8") as f_out:
                with Evtx(evtx_path) as evtx:
                    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                        try:
                            record_dict = {
                                "EventID": None, 
                                "RawXML": xml
                            }
                            f_out.write(json.dumps(record_dict) + "\n")
                        except: pass
        except Exception as e:
            print(f"Erreur EVTX: {e}")

    @staticmethod
    def ingest_all(file_path: str, workdir: str) -> dict:
        work = Path(workdir)
        if work.exists(): shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        
        # Structure
        zeek_dir = str(work / "zeek")
        suri_dir = str(work / "suricata")
        files_dir = str(work / "exported_objects")
        scanner_dir = str(work / "payload_scanner")
        triage_dir = str(work / "file_triage")
        evtx_dir = str(work / "evtx_json")
        
        for d in [scanner_dir, triage_dir, evtx_dir]:
            Path(d).mkdir(parents=True, exist_ok=True)

        manifest = {
            "zeek_logs": {}, "zeek_mode": "disabled",
            "suricata_eve": None, "suricata_mode": "disabled",
            "exported_files_jsonl": None, "payload_hits": None,
            "evtx_jsonl": None, "file_type": "unknown"
        }

        # Détection du type de fichier
        ext = str(file_path).lower()
        
        # CAS 1 : PCAP
        if ext.endswith(".pcap") or ext.endswith(".pcapng") or ext.endswith(".cap"):
            manifest["file_type"] = "pcap"
            try:
                logs, mode = PcapIngestor.run_zeek(file_path, zeek_dir)
                manifest["zeek_logs"] = logs
                manifest["zeek_mode"] = mode
            except: pass 
            
            try:
                eve, mode = PcapIngestor.run_suricata(file_path, suri_dir)
                manifest["suricata_eve"] = eve
                manifest["suricata_mode"] = mode
            except: pass
            
            # Export objets HTTP
            try:
                PcapIngestor.export_http_objects(file_path, files_dir)
            except: pass

            # Triage fichiers exportés
            try:
                out_triage = str(Path(triage_dir) / "exported_files.jsonl")
                triaged = FileTriage.hash_dir_to_jsonl(files_dir, out_triage)
                manifest["exported_files_jsonl"] = triaged
            except: pass

            # Payload scanner
            try:
                out_hits = str(Path(scanner_dir) / "payload_hits.jsonl")
                manifest["payload_hits"] = PcapIngestor.run_payload_scanner(file_path, out_hits)
            except: pass

        # CAS 2 : EVTX (Windows)
        elif ext.endswith(".evtx"):
            manifest["file_type"] = "evtx"
            jsonl_path = str(Path(evtx_dir) / "windows_events.jsonl")
            PcapIngestor.evtx_to_jsonl(file_path, jsonl_path)
            manifest["evtx_jsonl"] = jsonl_path

        return manifest