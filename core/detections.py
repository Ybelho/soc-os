import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.datalake import DataLake


@dataclass
class DetectionRule:
    rule_id: str
    severity: str
    title: str
    description: str
    sql: str


class DetectionEngine:
    def __init__(self, rules_dir: str = "detections"):
        self.rules_dir = Path(rules_dir)

    def load_rules(self) -> List[DetectionRule]:
        rules: List[DetectionRule] = []
        if not self.rules_dir.exists():
            return rules

        for p in sorted(self.rules_dir.glob("*.yaml")):
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not raw:
                continue
            rules.append(
                DetectionRule(
                    rule_id=raw["id"],
                    severity=raw.get("severity", "low"),
                    title=raw.get("title", raw["id"]),
                    description=raw.get("description", ""),
                    sql=raw["sql"].strip(),
                )
            )
        return rules

    def run(self, lake: DataLake, limit_rows: int = 25) -> Dict[str, Any]:
        rules = self.load_rules()
        alerts: List[Dict[str, Any]] = []

        # Table alerts stable
        lake.con.execute("""
        CREATE OR REPLACE TABLE alerts (
            rule_id VARCHAR,
            severity VARCHAR,
            title VARCHAR,
            description VARCHAR,
            count BIGINT,
            evidence_json VARCHAR
        );
        """)

        for r in rules:
            try:
                df = lake.con.execute(r.sql).df()
            except Exception:
                continue

            if df is None or df.empty:
                continue

            evidence = df.head(limit_rows).to_dict(orient="records")
            alerts.append({
                "rule_id": r.rule_id,
                "severity": r.severity,
                "title": r.title,
                "description": r.description,
                "count": int(len(df)),
                "evidence": evidence
            })

            lake.con.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)",
                [r.rule_id, r.severity, r.title, r.description, int(len(df)), json.dumps(evidence, ensure_ascii=False)]
            )

        return {"alerts": alerts}

    @staticmethod
    def to_markdown(alerts: List[Dict[str, Any]]) -> str:
        if not alerts:
            return "### ✅ Détections\nAucune règle n'a déclenché d'alerte."

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        alerts_sorted = sorted(alerts, key=lambda a: sev_rank.get(a["severity"], 0), reverse=True)

        lines = ["### 🚨 Détections (règles)"]
        for a in alerts_sorted:
            sev = a["severity"].upper()
            lines.append(f"\n#### [{sev}] {a['title']} (`{a['rule_id']}`)")
            if a.get("description"):
                lines.append(a["description"])
            lines.append(f"- **Occurrences:** {a.get('count', 0)}")
            # mini tableau preuve
            ev = a.get("evidence", [])[:8]
            if ev:
                # clés communes
                keys = list(ev[0].keys())
                header = "| " + " | ".join(keys) + " |"
                sep = "| " + " | ".join(["---"] * len(keys)) + " |"
                lines.append(header)
                lines.append(sep)
                for row in ev:
                    lines.append("| " + " | ".join(str(row.get(k, "")) for k in keys) + " |")
            lines.append("\n*(preuves = extrait des résultats SQL)*")

        return "\n".join(lines)

