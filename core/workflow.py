import os
from typing import TypedDict, List, Dict, Any, Optional
from core.visualization import Visualizer
import pandas as pd
import plotly.express as px
from langgraph.graph import StateGraph, END

from core.llm import call_ollama, call_ollama_structured
from core.datalake import DataLake
from core.cti import ThreatIntel
from core.detections import DetectionEngine

CHARTS_DIR = "public/charts"
os.makedirs(CHARTS_DIR, exist_ok=True)


class AgentState(TypedDict, total=False):
    objective: str
    db_path: str
    schema_info: str

    iteration: int
    max_iterations: int
    sql_history: List[str]
    evidence_items: List[dict]
    investigation_summary: str
    last_observation: str
    planned_action: dict

    generated_sql: str
    sql_results: str
    data_frames: dict
    cti_results: str
    detections_md: str
    visuals: List[str]
    final_answer: str
    current_task: str       # La mission donnée par le Stratège au SQL Agent
    task_result: str        # Le résultat (résumé) renvoyé par le SQL Agent
    router_decision: str    # "continue" ou "finish"


# ----------------------------
# Helpers
# ----------------------------
def _truncate(s: str, max_chars: int = 6000) -> str:
    if not s: return ""
    s = str(s)
    return s if len(s) <= max_chars else (s[:max_chars] + "\n\n[...truncated...]")

def _format_df(df: pd.DataFrame, limit: int = 40) -> str:
    if df is None or df.empty: return "Aucun résultat significatif."
    if len(df) > limit:
        return df.head(limit).to_markdown(index=False) + f"\n\n*(... {len(df)-limit} lignes masquées)*"
    return df.to_markdown(index=False)

def _sql_is_safe(sql: str) -> bool:
    if not sql: return False
    s = sql.strip().lower()
    bad = ["insert", "update", "delete", "drop", "alter", "create", "attach", "copy", "pragma"]
    if any(b in s for b in bad): return False
    return s.startswith("select") or s.startswith("with")

def _sql_is_public_ip(col: str) -> str:
    return f"""
    ({col} IS NOT NULL)
    AND NOT (
      {col} LIKE '10.%' OR {col} LIKE '192.168.%' OR {col} LIKE '127.%'
      OR regexp_matches({col}, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*')
    )
    """

def _push_evidence(state: AgentState, title: str, sql: str, df: Optional[pd.DataFrame]) -> List[dict]:
    # On récupère la liste actuelle ou une nouvelle
    items = list(state.get("evidence_items", []))
    evid_id = len(items)
    rowcount = 0 if df is None else int(len(df))
    preview = _format_df(df) if df is not None else "Aucun résultat."
    
    items.append({
        "id": evid_id,
        "title": title,
        "sql": sql,
        "rowcount": rowcount,
        "preview_md": preview
    })
    return items # On retourne la nouvelle liste pour mise à jour

def _evidence_markdown(evidence_items: List[dict], max_items: int = 30) -> str:
    out = []
    for it in evidence_items[:max_items]:
        out.append(
            f"### PREUVE {it['id']} — {it.get('title','')}\n"
            f"```sql\n{it.get('sql','')}\n```\n"
            f"{it.get('preview_md','')}\n"
        )
    if len(evidence_items) > max_items:
        out.append(f"\n*(... {len(evidence_items)-max_items} preuves supplémentaires masquées)*\n")
    return "\n\n".join(out)

def _recent_sql(state: AgentState, n: int = 8) -> str:
    hist = state.get("sql_history", [])
    tail = hist[-n:] if len(hist) > n else hist
    if not tail: return "(aucune)"
    return "\n\n".join(f"- {q.strip()}" for q in tail)

def _is_repeated_sql(state: AgentState, sql: str) -> bool:
    hist = [h.strip() for h in state.get("sql_history", [])]
    return sql.strip() in hist


# ----------------------------
# 0) SCOUT
# ----------------------------
def scout_node(state: AgentState):
    lake = DataLake(db_path=state["db_path"])
    
    # Init vars
    new_evidence = []
    new_history = []
    new_dfs = {}

    queries = [
        ("Inventory", "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema='main' ORDER BY 1"),
        ("Time range", "SELECT MIN(timestamp) AS start_ts, MAX(timestamp) AS end_ts, COUNT(*) AS total_events FROM events"),
        ("Timeline (per minute)", "SELECT date_trunc('minute', timestamp) AS time, COUNT(*) AS volume FROM events GROUP BY 1 ORDER BY 1"),
        ("Top src (events)", "SELECT src_ip, COUNT(*) AS volume FROM events WHERE src_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 25"),
        ("Top dst (events)", "SELECT dst_ip, COUNT(*) AS volume FROM events WHERE dst_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 25"),
        ("Top services", "SELECT service, COUNT(*) AS volume FROM events WHERE service IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 30"),
        ("Top dst ports", "SELECT dst_port, COUNT(*) AS volume FROM events WHERE dst_port IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 30"),
        ("Public destinations (top)", f"SELECT src_ip, dst_ip, dst_port, COUNT(*) AS volume FROM events WHERE ({_sql_is_public_ip('dst_ip')}) GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 40"),
        ("Payload hits count", "SELECT COUNT(*) AS payload_hits_count FROM payload_hits"),
        ("Exported files triage (top)", "SELECT filename, size, sha256, sha1, md5 FROM exported_files ORDER BY size DESC LIMIT 50"),
        # DNS
        ("DNS: top queried domains", "SELECT query, COUNT(*) AS hits FROM view_dns WHERE query IS NOT NULL GROUP BY 1 ORDER BY hits DESC LIMIT 50"),
        ("DNS: top sources", "SELECT src_ip, COUNT(*) AS dns_queries, COUNT(DISTINCT query) AS uniq_domains FROM view_dns WHERE src_ip IS NOT NULL AND query IS NOT NULL GROUP BY 1 ORDER BY dns_queries DESC LIMIT 25"),
        # TLS
        ("TLS: top SNI", "SELECT sni, COUNT(*) AS hits FROM view_tls WHERE sni IS NOT NULL GROUP BY 1 ORDER BY hits DESC LIMIT 50"),
        # HTTP
        ("HTTP: suspicious user agents", "SELECT user_agent, COUNT(*) AS hits FROM view_http WHERE user_agent IS NOT NULL GROUP BY 1 ORDER BY hits DESC LIMIT 50"),
    ]

    # Ajout conditionnel pour Suricata s'il existe
    try:
        if "suricata_eve" in _list_tables(lake):
             queries.append(("Suricata: alerts", "SELECT timestamp, src_ip, dest_ip, alert.signature, alert.severity FROM suricata_eve WHERE event_type='alert' LIMIT 50"))
    except: pass

    for title, sql in queries:
        try:
            df = lake.con.execute(sql).df()
            
            # Gestion manuelle de l'evidence pour le scout (car _push_evidence modifie in-place ce qui est risqué ici)
            rowcount = len(df)
            preview = _format_df(df)
            new_evidence.append({
                "id": len(new_evidence),
                "title": title,
                "sql": sql,
                "rowcount": rowcount,
                "preview_md": preview
            })
            new_history.append(sql)

            # charts data
            if "time" in df.columns and "volume" in df.columns and "Timeline" in title:
                new_dfs["timeline"] = df
            if title == "Top src (events)" and "src_ip" in df.columns:
                new_dfs["top_src"] = df
            if title == "Top services" and "service" in df.columns:
                new_dfs["services"] = df
        except Exception:
            pass

    # IMPORTANT: On retourne les nouvelles valeurs pour mettre à jour l'état
    return {
        "evidence_items": new_evidence,
        "sql_history": new_history,
        "data_frames": new_dfs,
        "sql_results": _evidence_markdown(new_evidence) # Pour compatibilité
    }

def _list_tables(lake):
    try: return set(r[0] for r in lake.con.execute("SELECT table_name FROM information_schema.tables").fetchall())
    except: return set()


# ----------------------------
# 1) VISUALIZER (Refondu)
# ----------------------------
def visualizer_node(state: AgentState):
    viz = Visualizer(state["db_path"])
    
    # 1. Graph Interactive (HTML)
    graph_path = viz.generate_network_graph()
    
    # 2. Charts (Plotly Objs)
    plotly_figs = viz.generate_plotly_objects()
    
    # On stocke tout dans le state
    visuals = []
    if graph_path:
        state["_network_graph_path"] = graph_path
        visuals.append("network_graph")
        
    for k, fig in plotly_figs.items():
        state[f"_plotly_{k}"] = fig
        visuals.append(f"plotly_{k}")
        
    return {"visuals": visuals}

# ----------------------------
# 2) DETECTIONS
# ----------------------------
def detection_node(state: AgentState):
    lake = DataLake(db_path=state["db_path"])
    engine = DetectionEngine(rules_dir="detections")
    out = engine.run(lake)
    md = engine.to_markdown(out.get("alerts", []))
    return {"detections_md": md}


# ----------------------------
# 3) CTI (CORRIGÉ - BUG TABLE ALERTS)
# ----------------------------
def cti_node(state: AgentState):
    lake = DataLake(db_path=state["db_path"])
    try:
        # CORRECTION : On ne requête plus la table 'alerts' directement car elle n'a pas de colonne ip explicite.
        # On se concentre sur les Payloads (C2 probable) et les Observables globaux.
        q = f"""
        WITH candidates AS (
            -- 1. Priorité aux destinations des payloads (souvent des C2)
            SELECT dst_ip as ip FROM payload_hits WHERE dst_ip IS NOT NULL
            
            UNION 
            
            -- 2. Échantillon des IPs publiques globales observées
            SELECT value as ip FROM observables WHERE type='ip'
        )
        SELECT DISTINCT ip 
        FROM candidates 
        WHERE ({_sql_is_public_ip('ip')}) 
        LIMIT 15
        """
        
        df = lake.con.execute(q).df()
        
        if df.empty:
            return {"cti_results": "Aucune IP publique suspecte détectée pour analyse CTI."}
            
        ips = df["ip"].dropna().astype(str).tolist()
        
        # Appel API
        ti = ThreatIntel()
        results = [ti.check_ip(ip) for ip in ips]
        
        return {"cti_results": ti.format_report(results)}
        
    except Exception as e:
        return {"cti_results": f"Erreur CTI interne : {str(e)}"}

# ----------------------------
# 4) PLANNER (CORRECTED)
# ----------------------------
PLANNER_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["sql", "stop"]},
        "title": {"type": "string"},
        "query": {"type": "string"},
        "why": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "stop_reason": {"type": "string"}
    },
    "required": ["action", "title", "why", "confidence"]
}

def planner_node(state: AgentState):
    # Initialisation locale pour lecture, mais on doit renvoyer les mises à jour
    iter_count = int(state.get("iteration", 0))
    max_iter = int(state.get("max_iterations", 4))

    # Hard stop budget
    if iter_count >= max_iter:
        return {
            "planned_action": {
                "action": "stop",
                "title": "Stop",
                "why": "Budget d'itérations atteint",
                "confidence": "high",
                "stop_reason": "max_iterations"
            },
            "last_observation": f"Stop: max_iterations={max_iter}"
        }

    # Préparation du contexte
    evid_md = _truncate(_evidence_markdown(state.get("evidence_items", []), max_items=18), 12000)
    det = _truncate(state.get("detections_md", ""), 6000)
    cti = _truncate(state.get("cti_results", ""), 2500)
    summ = _truncate(state.get("investigation_summary", ""), 6000)
    recent_sql = _truncate(_recent_sql(state, 8), 3000)

    prompt = f"""
Tu es un Analyste SOC senior en mode INVESTIGATION ITÉRATIVE.
Tu dois choisir le PROCHAIN pivot pour comprendre l'incident.

Règles STRICTES:
- Action = "sql" ou "stop".
- Si action="sql": query = DuckDB READ-ONLY (SELECT/WITH), toujours LIMIT <= 500.
- INTERDIT de répéter une requête déjà exécutée (voir SQL RECENT).
- Si tu as assez d'info pour conclure (IoCs identifiés, killchain claire) -> action="stop".
- Zéro invention.

OBJECTIF:
{state["objective"]}

RÉSUMÉ EN COURS:
{summ}

PREUVES ACTUELLES:
{evid_md}

SQL RECENT (INTERDIT DE RÉPÉTER):
{recent_sql}

Rends uniquement le JSON.
"""

    out = call_ollama_structured(
        model="qwen2.5-coder:7b",
        prompt=prompt,
        schema=PLANNER_SCHEMA,
        temperature=0.1,
        num_ctx=8192,
        timeout=180
    )

    if out.get("action") == "sql":
        out.setdefault("query", "")

    # IMPORTANT: On RETOURNE la planned_action pour mettre à jour l'état global
    return {
        "planned_action": out,
        "last_observation": f"Planned: {out.get('action')} — {out.get('title','')}"
    }


# ----------------------------
# 5) EXECUTOR (CORRECTED)
# ----------------------------
def executor_node(state: AgentState):
    plan = state.get("planned_action", {})
    action = plan.get("action", "stop")
    current_iter = int(state.get("iteration", 0))

    if action != "sql":
        return {"last_observation": f"No SQL executed (action={action})."}

    sql = (plan.get("query") or "").strip()
    
    # Safety checks
    if not _sql_is_safe(sql):
        return {
            "last_observation": "Planner proposed unsafe SQL; blocked.",
            "iteration": current_iter + 1 # On incrémente quand même pour éviter boucle infinie sur erreur
        }

    if _is_repeated_sql(state, sql):
        return {
            "last_observation": "Planner repeated SQL; skipping.",
            "iteration": current_iter + 1
        }

    lake = DataLake(db_path=state["db_path"])
    
    # Exécution
    try:
        df = lake.con.execute(sql).df()
        title = plan.get("title", "Pivot")
        
        # Mise à jour des preuves
        new_items = _push_evidence(state, title, sql, df)
        
        # Mise à jour de l'historique SQL
        new_history = list(state.get("sql_history", []))
        new_history.append(sql)
        
        new_generated_sql = ";\n\n".join(new_history) + ";"
        new_sql_results = _evidence_markdown(new_items)
        obs = f"Executed OK: {title} (rows={len(df)})"
        
        # IMPORTANT : On retourne TOUT ce qui a changé
        return {
            "evidence_items": new_items,
            "sql_history": new_history,
            "generated_sql": new_generated_sql,
            "sql_results": new_sql_results,
            "last_observation": obs,
            "iteration": current_iter + 1  # <--- L'INCREMENTATION CRITIQUE
        }

    except Exception as e:
        # En cas d'erreur, on loggue mais on continue
        # On ajoute quand même l'erreur aux preuves pour que le planner le sache
        new_items = _push_evidence(state, f"Error: {plan.get('title')}", sql, None)
        return {
            "evidence_items": new_items,
            "last_observation": f"SQL error: {e}",
            "iteration": current_iter + 1
        }
# =============================
# new NODES
# =============================
def strategist_node(state: AgentState):
    """
    Le Cerveau. Décide de la prochaine étape d'investigation sans se soucier du SQL.
    """
    summary = _truncate(state.get("investigation_summary", "Début de l'analyse."), 4000)
    alerts = _truncate(state.get("detections_md", ""), 2000)
    
    # On ne donne que les TITRES des preuves précédentes pour économiser des tokens
    evidence_titles = [f"- {e.get('title')}" for e in state.get("evidence_items", [])]
    evidence_history = "\n".join(evidence_titles[-10:]) or "(Aucune)"

    iter_idx = state.get("iteration", 0)
    
    prompt = f"""
    Tu es le CHEF DES OPÉRATIONS (SOC Manager).
    
    CONTEXTE ACTUEL:
    {summary}
    
    ALERTES DÉTECTÉES:
    {alerts}
    
    HISTORIQUE DES ACTIONS:
    {evidence_history}
    
    Ton but : Identifier la zone d'ombre la plus critique.
    
    Réponds UNIQUEMENT avec ce JSON :
    {{
        "next_step": "continue" ou "finish",
        "task": "La question précise à poser aux données (ex: 'Quels sont les user-agents de l'IP X ?')",
        "reason": "Pourquoi c'est important"
    }}
    
    Si tu as assez de preuves pour qualifier l'incident, mets "next_step": "finish".
    Budget restant : {4 - iter_idx} étapes.
    """
    
    try:
        res = call_ollama_structured("mistral", prompt, schema="json", temperature=0.2)
        return {
            "current_task": res.get("task", ""), 
            "router_decision": res.get("next_step", "continue")
        }
    except Exception as e:
        return {"router_decision": "continue", "current_task": "Investiguer les connexions suspectes génériques."}

def sql_specialist_node(state: AgentState):
    """
    L'Expert Technique. Transforme une question en langage naturel en SQL DuckDB.
    """
    task = state.get("current_task")
    schema = state.get("schema_info")
    lake = DataLake(state["db_path"])
    
    # Sécurité renforcée : on active le mode lecture seule de la DB
    lake.set_readonly()
    
    prompt = f"""
    Tu es un EXPERT SQL DUCKDB.
    
    SCHÉMA DE LA BASE (Tables et Vues):
    {schema}
    
    MISSION:
    {task}
    
    Consignes :
    1. Écris UNE seule requête SQL optimisée.
    2. Utilise UNIQUEMENT les tables listées (préfère les vues 'view_*' ou 'events').
    3. Ajoute toujours 'LIMIT 100'.
    4. Réponds uniquement avec le JSON : {{ "sql": "SELECT ...", "title": "Titre court" }}
    """
    
    try:
        res = call_ollama_structured("qwen2.5-coder:7b", prompt, schema="json", temperature=0.1)
        sql = res.get("sql", "")
        title = res.get("title", "Analyse SQL")
        
        # Exécution sécurisée
        df = lake.execute_safe(sql)
        
        # Mise à jour des preuves (comme avant)
        new_items = _push_evidence(state, title, sql, df)
        
        # Résumé technique pour le Stratège
        observation = f"SQL '{title}' exécuté. {len(df)} lignes trouvées."
        if not df.empty:
            observation += f"\nAperçu : {df.head(3).to_dict(orient='records')}"
            
        return {
            "evidence_items": new_items,
            "task_result": observation,
            "last_observation": observation
        }
        
    except Exception as e:
        return {"last_observation": f"Erreur SQL Agent: {e}", "task_result": "Échec technique de la requête."}

# ----------------------------
# 6) SUMMARIZER
# ----------------------------
def summarizer_node(state: AgentState):
    items = state.get("evidence_items", [])
    if not items:
        return {"investigation_summary": state.get("investigation_summary", "")}

    last = items[-1]
    title = last.get("title", "")
    rowcount = last.get("rowcount", 0)

    bullets = []
    if rowcount == 0:
        bullets.append(f"- **{title}**: aucun résultat.")
    else:
        bullets.append(f"- **{title}**: {rowcount} résultats.")

    prev = state.get("investigation_summary", "").strip()
    combined = (prev + "\n" + "\n".join(bullets)).strip() if prev else "\n".join(bullets)
    
    return {"investigation_summary": _truncate(combined, 12000)}


# ----------------------------
# 7) ROUTING
# ----------------------------
def should_continue(state: AgentState) -> str:
    plan = state.get("planned_action", {})
    iter_count = int(state.get("iteration", 0))
    max_iter = int(state.get("max_iterations", 4))

    if plan.get("action") == "stop":
        return "report"
    
    if iter_count >= max_iter:
        return "report"
        
    return "loop"


# ----------------------------
# 8) REPORTER (CORRIGÉ & OPTIMISÉ)
# ----------------------------
def reporter_node(state: AgentState):
    # 1. Gestion des Visualisations (Texte uniquement pour le rapport Markdown)
    # Les graphiques interactifs sont gérés par Chainlit dans app.py
    visuals = state.get("visuals", [])
    images_md = "\n### 📊 Visualisations Disponibles\n"
    if visuals:
        for v in visuals:
            # On nettoie le nom de la clé (ex: "plotly_timeline" -> "Timeline")
            clean_name = v.replace("plotly_", "").replace("_", " ").title()
            images_md += f"- Graphique interactif : **{clean_name}** (voir ci-dessus)\n"
    else:
        images_md += "(Aucune visualisation générée)\n"

    # 2. Préparation du contexte "Régime" (Pour éviter la saturation des tokens)
    # On ne garde que les 15 dernières preuves SQL et on coupe à 6000 caractères
    raw_evidence = _evidence_markdown(state.get("evidence_items", []), max_items=15)
    evid_md = _truncate(raw_evidence, 6000)
    
    # Résumé narratif (coupé à 4000 chars)
    summ = _truncate(state.get("investigation_summary", ""), 4000)
    
    # Détections (Prioritaire, on garde 5000 chars)
    det = _truncate(state.get("detections_md", ""), 5000)
    
    # CTI (coupé à 2000 chars)
    cti = _truncate(state.get("cti_results", ""), 2000)

    # 3. Le Prompt (Directif et Synthétique)
    prompt = f"""
    Tu es un Analyste SOC Senior. Rédige un rapport d'investigation SYNTHÉTIQUE et ACTIONNABLE.
    Ne baratine pas. Va droit au but.

    ### ALERTES SURICATA & DÉTECTIONS (Priorité Absolue):
    {det}

    ### INTELLIGENCE (CTI):
    {cti}

    ### CONTEXTE ET PREUVES TECHNIQUES (SQL):
    {summ}
    {evid_md}

    ### FORMAT ATTENDU (Markdown):
    # 📑 RAPPORT D'INCIDENT
    ## 1. Résumé Exécutif
    (3 phrases max : Quelle est l'attaque ? Qui est la victime ? Qui est l'attaquant ? Confirme l'infection si preuves présentes).

    ## 2. Analyse Technique
    (Détaille les faits : Payloads suspects trouvés, IPs C2, Domaines DGA, etc. Cite les preuves).

    ## 3. Conclusion & Remediation
    (Actions immédiates à prendre : Isoler machine X, Bloquer IP Y).

    Réponds en Français.
    """

    # 4. Appel LLM avec Timeout Augmenté (600s = 10 minutes)
    try:
        answer = call_ollama("mistral", prompt, temperature=0.2, num_ctx=8192, timeout=600)
    except Exception as e:
        answer = f"⚠️ Le rapport n'a pas pu être généré entièrement par l'IA (Erreur: {e}). Veuillez consulter les données brutes ci-dessous."

    # 5. Assemblage final
    # On colle la réponse de l'IA + les données brutes en annexe pour l'analyste
    final = (
        answer.strip()
        + "\n\n---\n\n"
        + "### 🔍 Annexes Techniques & Données Brutes\n"
        + det
        + "\n\n"
        + cti
        + "\n\n"
        + images_md
    )

    return {"final_answer": "Analyse terminée. Dashboard généré."}

def build_agent():
    workflow = StateGraph(AgentState)
    
    # Nœuds Actifs
    workflow.add_node("scout", scout_node)
    workflow.add_node("viz", visualizer_node)
    workflow.add_node("detections", detection_node)
    workflow.add_node("cti", cti_node)
    
    workflow.add_node("strategist", strategist_node)
    workflow.add_node("sql_agent", sql_specialist_node)
    workflow.add_node("summarizer", summarizer_node)
    workflow.add_node("report", reporter_node)
    
    # Helper pour la boucle
    def next_iter(state):
        return {"iteration": state.get("iteration", 0) + 1}
    workflow.add_node("next_loop", next_iter)

    # Flux Principal
    workflow.set_entry_point("scout")
    workflow.add_edge("scout", "viz")
    workflow.add_edge("viz", "detections")
    workflow.add_edge("detections", "cti")
    workflow.add_edge("cti", "strategist") 

    # Logique conditionnelle du Stratège
    def route_strategy(state):
        decision = state.get("router_decision", "continue")
        iteration = state.get("iteration", 0)
        # Force le rapport si on dépasse le budget
        if decision == "finish" or iteration >= state.get("max_iterations", 4):
            return "report"
        return "sql_agent"

    workflow.add_conditional_edges(
        "strategist",
        route_strategy,
        {"sql_agent": "sql_agent", "report": "report"}
    )
    
    # Boucle de retour : SQL -> Summarizer -> Next Iter -> Strategist
    workflow.add_edge("sql_agent", "summarizer")
    workflow.add_edge("summarizer", "next_loop")
    workflow.add_edge("next_loop", "strategist")
    
    workflow.add_edge("report", END)
    
    return workflow.compile()