import os
import json
import time
import ipaddress
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional


class ThreatIntel:
    """
    CTI via AbuseIPDB (optionnel).
    - Pas de clé hardcodée.
    - Cache local pour éviter quota.
    """

    def __init__(self, api_key: Optional[str] = None, cache_path: str = "data/cti_cache.json"):
        self.api_key = api_key or os.getenv("ABUSEIPDB_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {'Key': self.api_key or "", 'Accept': 'application/json'}

        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache: Dict[str, Any] = {}
        if self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}

    def _cache_get(self, ip: str) -> Optional[dict]:
        item = self.cache.get(ip)
        if not item:
            return None
        # TTL 7 jours
        if time.time() - item.get("_ts", 0) > 7 * 24 * 3600:
            return None
        return item.get("data")

    def _cache_set(self, ip: str, data: dict):
        self.cache[ip] = {"_ts": time.time(), "data": data}
        try:
            self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def is_public_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_multicast
        except ValueError:
            return False

    def check_ip(self, ip: str) -> dict:
        if not self.is_public_ip(ip):
            return {"skipped": "IP Privée/Locale"}

        if not self.api_key:
            return {"error": "ABUSEIPDB_KEY manquante (ENV)."}

        cached = self._cache_get(ip)
        if cached:
            return cached

        try:
            url = f"{self.base_url}/check"
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            response = requests.get(url, headers=self.headers, params=params, timeout=7)

            if response.status_code == 200:
                d = response.json().get("data", {})
                data = {
                    "ip": d.get("ipAddress"),
                    "score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", "?"),
                    "isp": d.get("isp", "?"),
                    "usage": d.get("usageType", "?"),
                    "total_reports": d.get("totalReports", 0),
                }
                self._cache_set(ip, data)
                return data

            if response.status_code == 429:
                return {"error": "Quota API dépassé (AbuseIPDB)."}

            return {"error": f"Status {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def format_report(self, results: List[dict]) -> str:
        if not results:
            return "Aucune IP publique suspecte analysée."

        rows = []
        for res in results:
            if "error" in res or "skipped" in res:
                continue
            score = int(res.get("score", 0))
            score_display = f"🔴 **{score}%**" if score >= 50 else f"🟢 {score}%"
            rows.append(
                f"| {res.get('ip','?')} | {score_display} | {res.get('country','?')} | {res.get('isp','?')} | {res.get('usage','?')} |"
            )

        if not rows:
            return "Aucune menace externe détectée (ou IPs privées uniquement)."

        md = "### 🌍 THREAT INTELLIGENCE (AbuseIPDB)\n"
        md += "| IP | Score | Pays | FAI | Usage |\n"
        md += "|---|---:|---|---|---|\n"
        md += "\n".join(rows)
        return md
