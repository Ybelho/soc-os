import duckdb
import os
from pathlib import Path
from typing import Optional, List, Set
import pandas as pd

class DataLake:
    def __init__(self, db_path: str = "data/soc_lake.db"):
        Path(os.path.dirname(db_path)).mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.con = duckdb.connect(db_path)

    def reset(self):
        # drop views
        for v in [
            "events",
            "view_http", "view_dns", "view_files", "view_tls",
            "view_suri_alerts", "view_suri_dns", "view_suri_http",
            "view_suri_tls", "view_suri_files", "view_suri_flow",
            "observables",
        ]:
            try:
                self.con.execute(f"DROP VIEW IF EXISTS {v};")
            except Exception:
                pass

        # drop tables
        tables = self.con.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema='main'
        """).fetchall()

        for (t,) in tables:
            try:
                self.con.execute(f"DROP TABLE IF EXISTS {t};")
            except Exception:
                pass

    def ingest_jsonl(self, table: str, path: str):
        path = str(Path(path))

        q_strict = f"""
        CREATE OR REPLACE TABLE {table} AS
        SELECT * FROM read_json_auto(
            '{path}',
            format='newline_delimited',
            sample_size=2000000,
            maximum_depth=20,
            union_by_name=true
        );
        """

        q_fallback = f"""
        CREATE OR REPLACE TABLE {table} AS
        SELECT * FROM read_json_auto(
            '{path}',
            format='newline_delimited',
            sample_size=2000000,
            maximum_depth=20,
            union_by_name=true,
            ignore_errors=true
        );
        """

        try:
            self.con.execute(q_strict)
        except Exception:
            self.con.execute(q_fallback)

    def _create_empty_payload_hits(self):
        self.con.execute("""
        CREATE OR REPLACE TABLE payload_hits (
            timestamp DOUBLE,
            proto VARCHAR,
            src_ip VARCHAR,
            dst_ip VARCHAR,
            src_port INTEGER,
            dst_port INTEGER,
            stream_id INTEGER,
            pattern VARCHAR,
            confidence VARCHAR,
            match VARCHAR,
            context VARCHAR,
            flow_key VARCHAR
        );
        """)

    def _create_empty_exported_files(self):
        self.con.execute("""
        CREATE OR REPLACE TABLE exported_files (
            path VARCHAR,
            filename VARCHAR,
            size BIGINT,
            sha256 VARCHAR,
            sha1 VARCHAR,
            md5 VARCHAR
        );
        """)

    # -------------------------
    # Introspection helpers
    # -------------------------
    def _tables(self) -> Set[str]:
        try:
            return set(r[0] for r in self.con.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema='main'
            """).fetchall())
        except Exception:
            return set()

    def _views(self) -> Set[str]:
        try:
            return set(r[0] for r in self.con.execute("""
                SELECT table_name
                FROM information_schema.views
                WHERE table_schema='main'
            """).fetchall())
        except Exception:
            return set()

    def ingest_manifest(self, manifest: dict):
        # Zeek logs
        for name, path in manifest.get("zeek_logs", {}).items():
            try:
                self.ingest_jsonl(f"zeek_{name}", path)
            except Exception as e:
                print(f"[WARN] DuckDB ingest failed for zeek_{name}: {e}")

        # Suricata
        eve = manifest.get("suricata_eve")
        if eve and os.path.exists(eve):
            try:
                self.ingest_jsonl("suricata_eve", eve)
            except Exception as e:
                print(f"[WARN] DuckDB ingest failed for suricata_eve: {e}")

        # Exported files triage
        triage = manifest.get("exported_files_jsonl")
        if triage and os.path.exists(triage):
            try:
                if os.path.getsize(triage) == 0:
                    self._create_empty_exported_files()
                else:
                    self.ingest_jsonl("exported_files", triage)
            except Exception as e:
                print(f"[WARN] DuckDB ingest failed for exported_files: {e}")
                try:
                    self._create_empty_exported_files()
                except Exception:
                    pass
        else:
            try:
                self._create_empty_exported_files()
            except Exception:
                pass

        # Payload hits
        hits = manifest.get("payload_hits")
        if hits and os.path.exists(hits):
            try:
                if os.path.getsize(hits) == 0:
                    self._create_empty_payload_hits()
                else:
                    self.ingest_jsonl("payload_hits", hits)
            except Exception as e:
                print(f"[WARN] DuckDB ingest failed for payload_hits: {e}")
                try:
                    self._create_empty_payload_hits()
                except Exception:
                    pass
        else:
            try:
                self._create_empty_payload_hits()
            except Exception:
                pass

        self._build_views_best_effort()
        self.create_specialized_views()
        self._create_observables_view_best_effort()

    # -------------------------
    # Helpers column picking
    # -------------------------
    def _get_columns(self, table_name: str) -> List[str]:
        try:
            rows = self.con.execute(f"DESCRIBE {table_name}").fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []

    def _pick_first(self, cols: List[str], candidates: List[str]) -> Optional[str]:
        for c in candidates:
            if c in cols:
                return f"\"{c}\"" if "." in c else c
        return None

    def _pick_zeek_id_field(self, cols: List[str], field: str) -> Optional[str]:
        flat = f"id_{field}"
        if flat in cols:
            return flat
        dotted = f"id.{field}"
        if dotted in cols:
            return f"\"{dotted}\""
        if "id" in cols:
            return f"id.{field}"
        return None

    # -------------------------
    # events view
    # -------------------------
    def _build_views_best_effort(self):
        try:
            self._build_views()
        except Exception as e:
            print(f"[WARN] Failed to build views: {e}")
            try:
                self.con.execute("DROP VIEW IF EXISTS events;")
            except Exception:
                pass

    def _build_views(self):
        existing = self._tables()
        parts = []

        # ZEEK CONN -> events
        if "zeek_conn" in existing:
            cols = self._get_columns("zeek_conn")

            ts = self._pick_first(cols, ["ts", "timestamp"])
            src_ip = self._pick_zeek_id_field(cols, "orig_h")
            dst_ip = self._pick_zeek_id_field(cols, "resp_h")
            src_port = self._pick_zeek_id_field(cols, "orig_p")
            dst_port = self._pick_zeek_id_field(cols, "resp_p")

            proto = self._pick_first(cols, ["proto"])
            service = self._pick_first(cols, ["service"])
            duration = self._pick_first(cols, ["duration"])
            orig_bytes = self._pick_first(cols, ["orig_bytes"])
            resp_bytes = self._pick_first(cols, ["resp_bytes"])

            if ts and src_ip and dst_ip:
                parts.append(f"""
                    SELECT
                      'zeek_conn' AS source,
                      to_timestamp({ts}) AS timestamp,
                      {src_ip} AS src_ip,
                      {dst_ip} AS dst_ip,
                      {src_port if src_port else 'NULL::INT'} AS src_port,
                      {dst_port if dst_port else 'NULL::INT'} AS dst_port,
                      {proto if proto else "'?'"} AS proto,
                      {service if service else "NULL"} AS service,
                      {duration if duration else 'NULL::DOUBLE'} AS duration,
                      {orig_bytes if orig_bytes else 'NULL::BIGINT'} AS orig_bytes,
                      {resp_bytes if resp_bytes else 'NULL::BIGINT'} AS resp_bytes
                    FROM zeek_conn
                """)

        # SURICATA EVE -> events
        if "suricata_eve" in existing:
            cols = self._get_columns("suricata_eve")

            ts = self._pick_first(cols, ["timestamp"])
            src_ip = self._pick_first(cols, ["src_ip"])
            dst_ip = self._pick_first(cols, ["dest_ip", "dst_ip"])
            src_port = self._pick_first(cols, ["src_port"])
            dst_port = self._pick_first(cols, ["dest_port", "dst_port"])
            proto = self._pick_first(cols, ["proto"])
            event_type = self._pick_first(cols, ["event_type"])
            app_proto = self._pick_first(cols, ["app_proto"])

            if ts and src_ip and dst_ip:
                service_expr = "NULL"
                if app_proto and event_type:
                    service_expr = f"COALESCE({app_proto}, {event_type})"
                elif app_proto:
                    service_expr = app_proto
                elif event_type:
                    service_expr = event_type

                parts.append(f"""
                    SELECT
                      'suricata' AS source,
                      TRY_CAST({ts} AS TIMESTAMP) AS timestamp,
                      {src_ip} AS src_ip,
                      {dst_ip} AS dst_ip,
                      {src_port if src_port else 'NULL::INT'} AS src_port,
                      {dst_port if dst_port else 'NULL::INT'} AS dst_port,
                      {proto if proto else "'?'"} AS proto,
                      {service_expr} AS service,
                      NULL::DOUBLE AS duration,
                      NULL::BIGINT AS orig_bytes,
                      NULL::BIGINT AS resp_bytes
                    FROM suricata_eve
                    WHERE {src_ip} IS NOT NULL
                """)

        if parts:
            self.con.execute("CREATE OR REPLACE VIEW events AS " + "\nUNION ALL\n".join(parts))
        else:
            self.con.execute("DROP VIEW IF EXISTS events;")

    # -------------------------
    # Specialized views (Zeek + Suricata + fallbacks)
    # -------------------------
    def _ensure_empty_view(self, view_name: str, select_sql: str):
        """
        select_sql must be a SELECT ... WHERE 1=0 with proper typed columns.
        """
        try:
            self.con.execute(f"CREATE OR REPLACE VIEW {view_name} AS {select_sql}")
        except Exception:
            pass

    def create_specialized_views(self):
        print("🔨 Création des vues spécialisées (Zeek + Suricata)...")

        existing = self._tables()

        # -------- Zeek-derived views (best effort) --------
        # view_http
        if "zeek_http" in existing:
            cols = self._get_columns("zeek_http")
            ts = self._pick_first(cols, ["ts", "timestamp"])
            src_ip = self._pick_zeek_id_field(cols, "orig_h")
            dst_ip = self._pick_zeek_id_field(cols, "resp_h")
            dst_port = self._pick_zeek_id_field(cols, "resp_p")

            method = self._pick_first(cols, ["method"])
            host = self._pick_first(cols, ["host"])
            uri = self._pick_first(cols, ["uri"])
            ua = self._pick_first(cols, ["user_agent"])
            status = self._pick_first(cols, ["status_code"])
            resp_len = self._pick_first(cols, ["response_body_len", "resp_body_len"])

            if ts and src_ip and dst_ip:
                try:
                    self.con.execute(f"""
                        CREATE OR REPLACE VIEW view_http AS
                        SELECT
                          to_timestamp({ts}) AS timestamp,
                          {src_ip} AS src_ip,
                          {dst_ip} AS dst_ip,
                          {dst_port if dst_port else 'NULL::INT'} AS dst_port,
                          {method if method else 'NULL'} AS method,
                          {host if host else 'NULL'} AS host,
                          {uri if uri else 'NULL'} AS uri,
                          {ua if ua else 'NULL'} AS user_agent,
                          {status if status else 'NULL'} AS status_code,
                          {resp_len if resp_len else 'NULL'} AS response_body_len
                        FROM zeek_http
                    """)
                except Exception:
                    pass

        # view_dns
        if "zeek_dns" in existing:
            cols = self._get_columns("zeek_dns")
            ts = self._pick_first(cols, ["ts", "timestamp"])
            src_ip = self._pick_zeek_id_field(cols, "orig_h")
            dst_ip = self._pick_zeek_id_field(cols, "resp_h")

            query = self._pick_first(cols, ["query"])
            qtype = self._pick_first(cols, ["qtype_name", "qtype"])
            rcode = self._pick_first(cols, ["rcode_name", "rcode"])
            answers = self._pick_first(cols, ["answers"])

            if ts and query:
                try:
                    self.con.execute(f"""
                        CREATE OR REPLACE VIEW view_dns AS
                        SELECT
                          to_timestamp({ts}) AS timestamp,
                          {src_ip if src_ip else 'NULL'} AS src_ip,
                          {dst_ip if dst_ip else 'NULL'} AS dst_ip,
                          {query} AS query,
                          {qtype if qtype else 'NULL'} AS qtype_name,
                          {rcode if rcode else 'NULL'} AS rcode_name,
                          {answers if answers else 'NULL'} AS answers
                        FROM zeek_dns
                    """)
                except Exception:
                    pass

        # view_tls
        if "zeek_ssl" in existing or "zeek_tls" in existing:
            table = "zeek_tls" if "zeek_tls" in existing else "zeek_ssl"
            cols = self._get_columns(table)
            ts = self._pick_first(cols, ["ts", "timestamp"])
            src_ip = self._pick_zeek_id_field(cols, "orig_h")
            dst_ip = self._pick_zeek_id_field(cols, "resp_h")
            server_name = self._pick_first(cols, ["server_name", "sni"])
            ja3 = self._pick_first(cols, ["ja3"])
            version = self._pick_first(cols, ["version"])
            cipher = self._pick_first(cols, ["cipher"])

            if ts and (server_name or ja3):
                try:
                    self.con.execute(f"""
                        CREATE OR REPLACE VIEW view_tls AS
                        SELECT
                          to_timestamp({ts}) AS timestamp,
                          {src_ip if src_ip else 'NULL'} AS src_ip,
                          {dst_ip if dst_ip else 'NULL'} AS dst_ip,
                          {server_name if server_name else 'NULL'} AS sni,
                          {ja3 if ja3 else 'NULL'} AS ja3,
                          {version if version else 'NULL'} AS tls_version,
                          {cipher if cipher else 'NULL'} AS cipher
                        FROM {table}
                    """)
                except Exception:
                    pass

        # view_files
        if "zeek_files" in existing:
            cols = self._get_columns("zeek_files")
            ts = self._pick_first(cols, ["ts", "timestamp"])
            mime = self._pick_first(cols, ["mime_type"])
            filename = self._pick_first(cols, ["filename"])
            sha1 = self._pick_first(cols, ["sha1"])
            md5 = self._pick_first(cols, ["md5"])
            total = self._pick_first(cols, ["total_bytes"])
            tx = self._pick_first(cols, ["tx_hosts"])
            rx = self._pick_first(cols, ["rx_hosts"])

            if ts:
                try:
                    self.con.execute(f"""
                        CREATE OR REPLACE VIEW view_files AS
                        SELECT
                          to_timestamp({ts}) AS timestamp,
                          CASE WHEN {tx} IS NULL THEN NULL ELSE {tx}[1] END AS src_ip,
                          CASE WHEN {rx} IS NULL THEN NULL ELSE {rx}[1] END AS dst_ip,
                          {mime if mime else 'NULL'} AS mime_type,
                          {filename if filename else 'NULL'} AS filename,
                          {md5 if md5 else 'NULL'} AS md5,
                          {sha1 if sha1 else 'NULL'} AS sha1,
                          {total if total else 'NULL'} AS total_bytes
                        FROM zeek_files
                    """)
                except Exception:
                    pass

        # -------- Suricata pivot views (best effort) --------
        if "suricata_eve" in existing:
            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_suri_alerts AS
                    SELECT
                      TRY_CAST(timestamp AS TIMESTAMP) AS timestamp,
                      flow_id,
                      src_ip,
                      src_port,
                      dest_ip AS dst_ip,
                      dest_port AS dst_port,
                      proto,
                      app_proto,
                      event_type,
                      alert.signature_id AS signature_id,
                      alert.signature AS signature,
                      alert.category AS category,
                      alert.severity AS severity,
                      pcap_cnt
                    FROM suricata_eve
                    WHERE event_type = 'alert'
                """)
            except Exception:
                pass

            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_suri_dns AS
                    SELECT
                      TRY_CAST(timestamp AS TIMESTAMP) AS timestamp,
                      flow_id,
                      src_ip,
                      src_port,
                      dest_ip AS dst_ip,
                      dest_port AS dst_port,
                      proto,
                      dns.type AS dns_type,
                      dns.rrname AS rrname,
                      dns.rrtype AS rrtype,
                      dns.rdata AS rdata,
                      dns.tx_id AS tx_id
                    FROM suricata_eve
                    WHERE event_type = 'dns'
                """)
            except Exception:
                pass

            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_suri_http AS
                    SELECT
                      TRY_CAST(timestamp AS TIMESTAMP) AS timestamp,
                      flow_id,
                      src_ip,
                      src_port,
                      dest_ip AS dst_ip,
                      dest_port AS dst_port,
                      proto,
                      http.hostname AS host,
                      http.url AS url,
                      http.http_method AS method,
                      http.user_agent AS user_agent,
                      http.status AS status
                    FROM suricata_eve
                    WHERE event_type = 'http'
                """)
            except Exception:
                pass

            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_suri_tls AS
                    SELECT
                      TRY_CAST(timestamp AS TIMESTAMP) AS timestamp,
                      flow_id,
                      src_ip,
                      src_port,
                      dest_ip AS dst_ip,
                      dest_port AS dst_port,
                      proto,
                      tls.sni AS sni,
                      tls.version AS version,
                      tls.subject AS subject,
                      tls.issuerdn AS issuer,
                      tls.fingerprint AS fingerprint
                    FROM suricata_eve
                    WHERE event_type = 'tls'
                """)
            except Exception:
                pass

            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_suri_files AS
                    SELECT
                      TRY_CAST(timestamp AS TIMESTAMP) AS timestamp,
                      flow_id,
                      src_ip,
                      src_port,
                      dest_ip AS dst_ip,
                      dest_port AS dst_port,
                      proto,
                      fileinfo.filename AS filename,
                      fileinfo.size AS size,
                      fileinfo.sha256 AS sha256,
                      fileinfo.md5 AS md5,
                      fileinfo.sha1 AS sha1,
                      fileinfo.stored AS stored
                    FROM suricata_eve
                    WHERE event_type = 'fileinfo'
                """)
            except Exception:
                pass

        # -------- Fallbacks: ensure view_dns/view_tls/view_http/view_files exist --------
        views = self._views()

        # DNS fallback from Suricata if Zeek DNS absent
        if "view_dns" not in views and "view_suri_dns" in views:
            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_dns AS
                    SELECT
                      timestamp,
                      src_ip,
                      dst_ip,
                      rrname AS query,
                      rrtype AS qtype_name,
                      NULL::VARCHAR AS rcode_name,
                      rdata AS answers
                    FROM view_suri_dns
                """)
            except Exception:
                pass

        # TLS fallback from Suricata if Zeek TLS absent
        views = self._views()
        if "view_tls" not in views and "view_suri_tls" in views:
            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_tls AS
                    SELECT
                      timestamp,
                      src_ip,
                      dst_ip,
                      sni,
                      NULL::VARCHAR AS ja3,
                      version AS tls_version,
                      NULL::VARCHAR AS cipher
                    FROM view_suri_tls
                """)
            except Exception:
                pass

        # HTTP fallback from Suricata if Zeek HTTP absent
        views = self._views()
        if "view_http" not in views and "view_suri_http" in views:
            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_http AS
                    SELECT
                      timestamp,
                      src_ip,
                      dst_ip,
                      dst_port,
                      method,
                      host,
                      url AS uri,
                      user_agent,
                      status AS status_code,
                      NULL::BIGINT AS response_body_len
                    FROM view_suri_http
                """)
            except Exception:
                pass

        # Files fallback from Suricata if Zeek files absent
        views = self._views()
        if "view_files" not in views and "view_suri_files" in views:
            try:
                self.con.execute("""
                    CREATE OR REPLACE VIEW view_files AS
                    SELECT
                      timestamp,
                      src_ip,
                      dst_ip,
                      NULL::VARCHAR AS mime_type,
                      filename,
                      md5,
                      sha1,
                      size AS total_bytes
                    FROM view_suri_files
                """)
            except Exception:
                pass

        # Finally: if still missing, create empty stable views to avoid SQL failures
        views = self._views()
        if "view_dns" not in views:
            self._ensure_empty_view(
                "view_dns",
                """
                SELECT
                  NULL::TIMESTAMP AS timestamp,
                  NULL::VARCHAR AS src_ip,
                  NULL::VARCHAR AS dst_ip,
                  NULL::VARCHAR AS query,
                  NULL::VARCHAR AS qtype_name,
                  NULL::VARCHAR AS rcode_name,
                  NULL::VARCHAR AS answers
                WHERE 1=0
                """
            )

        views = self._views()
        if "view_tls" not in views:
            self._ensure_empty_view(
                "view_tls",
                """
                SELECT
                  NULL::TIMESTAMP AS timestamp,
                  NULL::VARCHAR AS src_ip,
                  NULL::VARCHAR AS dst_ip,
                  NULL::VARCHAR AS sni,
                  NULL::VARCHAR AS ja3,
                  NULL::VARCHAR AS tls_version,
                  NULL::VARCHAR AS cipher
                WHERE 1=0
                """
            )

        views = self._views()
        if "view_http" not in views:
            self._ensure_empty_view(
                "view_http",
                """
                SELECT
                  NULL::TIMESTAMP AS timestamp,
                  NULL::VARCHAR AS src_ip,
                  NULL::VARCHAR AS dst_ip,
                  NULL::INT AS dst_port,
                  NULL::VARCHAR AS method,
                  NULL::VARCHAR AS host,
                  NULL::VARCHAR AS uri,
                  NULL::VARCHAR AS user_agent,
                  NULL::INT AS status_code,
                  NULL::BIGINT AS response_body_len
                WHERE 1=0
                """
            )

        views = self._views()
        if "view_files" not in views:
            self._ensure_empty_view(
                "view_files",
                """
                SELECT
                  NULL::TIMESTAMP AS timestamp,
                  NULL::VARCHAR AS src_ip,
                  NULL::VARCHAR AS dst_ip,
                  NULL::VARCHAR AS mime_type,
                  NULL::VARCHAR AS filename,
                  NULL::VARCHAR AS md5,
                  NULL::VARCHAR AS sha1,
                  NULL::BIGINT AS total_bytes
                WHERE 1=0
                """
            )

    # -------------------------
    # Observables unified view
    # -------------------------
    def _create_observables_view_best_effort(self):
        try:
            self.con.execute("DROP VIEW IF EXISTS observables;")
        except Exception:
            pass

        tables = self._tables()
        views = self._views()

        union_parts = []

        # IPs
        if "events" in views:
            union_parts.append("""
                SELECT 'ip' AS type, src_ip AS value FROM events WHERE src_ip IS NOT NULL
                UNION ALL
                SELECT 'ip' AS type, dst_ip AS value FROM events WHERE dst_ip IS NOT NULL
            """)

        # Domains (DNS)
        if "view_dns" in views:
            union_parts.append("""
                SELECT 'domain' AS type, query AS value
                FROM view_dns
                WHERE query IS NOT NULL
            """)

        # SNI (TLS)
        if "view_tls" in views:
            union_parts.append("""
                SELECT 'sni' AS type, sni AS value
                FROM view_tls
                WHERE sni IS NOT NULL
            """)

        # Hashes from view_files
        if "view_files" in views:
            union_parts.append("""
                SELECT 'hash_md5' AS type, md5 AS value FROM view_files WHERE md5 IS NOT NULL
                UNION ALL
                SELECT 'hash_sha1' AS type, sha1 AS value FROM view_files WHERE sha1 IS NOT NULL
            """)

        # Hashes from exported_files triage
        if "exported_files" in tables:
            union_parts.append("""
                SELECT 'hash_sha256' AS type, sha256 AS value FROM exported_files WHERE sha256 IS NOT NULL
                UNION ALL
                SELECT 'hash_sha1' AS type, sha1 AS value FROM exported_files WHERE sha1 IS NOT NULL
                UNION ALL
                SELECT 'hash_md5' AS type, md5 AS value FROM exported_files WHERE md5 IS NOT NULL
            """)

        # Hashes from Suricata fileinfo
        if "view_suri_files" in views:
            union_parts.append("""
                SELECT 'hash_sha256' AS type, sha256 AS value FROM view_suri_files WHERE sha256 IS NOT NULL
                UNION ALL
                SELECT 'hash_sha1' AS type, sha1 AS value FROM view_suri_files WHERE sha1 IS NOT NULL
                UNION ALL
                SELECT 'hash_md5' AS type, md5 AS value FROM view_suri_files WHERE md5 IS NOT NULL
            """)

        if not union_parts:
            return

        try:
            self.con.execute("""
                CREATE OR REPLACE VIEW observables AS
                SELECT DISTINCT type, value
                FROM (
            """ + "\nUNION ALL\n".join(union_parts) + """
                ) t
                WHERE value IS NOT NULL
            """)
        except Exception as e:
            print(f"[WARN] observables view build failed: {e}")

    def get_schema(self) -> str:
        tables = self.con.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema='main'
            ORDER BY 1
        """).fetchall()

        views = self.con.execute("""
            SELECT table_name
            FROM information_schema.views
            WHERE table_schema='main'
            ORDER BY 1
        """).fetchall()

        md = ["## Views disponibles"]
        if not views:
            md.append("- (aucune)")
        else:
            for (v,) in views:
                md.append(f"- {v}")

        md.append("\n## Tables disponibles")
        if not tables:
            md.append("- (aucune)")
        else:
            for (t,) in tables:
                cols = self.con.execute(f"DESCRIBE {t}").df()
                md.append(f"\n### {t}\n" + cols.to_markdown(index=False))

        return "\n".join(md)
    
    def set_readonly(self):
        """
        Interdit toute modification ultérieure (INSERT/DROP/UPDATE).
        Essentiel avant de laisser le LLM générer du SQL.
        """
        try:
            # DuckDB permet de configurer l'accès au niveau de la connexion
            self.con.execute("SET access_mode='READ_ONLY'")
        except Exception as e:
            print(f"[WARN] Impossible de passer en Read-Only : {e}")

    def execute_safe(self, sql: str) -> pd.DataFrame:
        """Exécute du SQL en mode protégé et retourne un DataFrame."""
        # Double sécurité : check mots-clés + mode readonly duckdb
        sql_lower = sql.strip().lower()
        forbidden = ["drop ", "insert ", "update ", "delete ", "alter ", "truncate "]
        if any(bad in sql_lower for bad in forbidden):
            raise ValueError("Sécurité: Requête modification interdite.")
        
        return self.con.execute(sql).df()
