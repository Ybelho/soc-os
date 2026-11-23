import os
import uuid
import chainlit as cl
import pandas as pd

from core.ingestion import PcapIngestor
from core.datalake import DataLake
from core.workflow import build_agent
from core.llm import call_ollama

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

@cl.on_chat_start
async def start():
    # Session Init
    run_id = uuid.uuid4().hex[:12]
    db_path = os.path.join(DATA_DIR, f"soc_lake_{run_id}.db")
    cl.user_session.set("run_id", run_id)
    cl.user_session.set("db_path", db_path)
    cl.user_session.set("mode", "ingestion") # Modes: ingestion, analyzing, chat

    await cl.Message(content=f"👋 **SOC-OS V2**\nDashboard Hybride & Logs Windows prêts.\n`ID: {run_id}`").send()
    
    files = await cl.AskFileMessage(
        content="Déposez un fichier (PCAP, EVTX) pour lancer le Dashboard d'Investigation.",
        accept={"application/octet-stream": [".pcap", ".pcapng", ".cap", ".evtx"]},
        max_size_mb=200, timeout=600
    ).send()

    file = files[0]
    # Logique de copie de fichier
    pcap_path = os.path.join(DATA_DIR, f"capture_{run_id}{os.path.splitext(file.name)[1]}")
    with open(file.path, "rb") as f_src:
        with open(pcap_path, "wb") as f_dst: f_dst.write(f_src.read())

    # 1. Ingestion
    status = cl.Message(content="⚙️ **ETL en cours...** (Zeek/Suricata/EVTX/Graph)")
    await status.send()
    
    artifacts_dir = os.path.join(DATA_DIR, "artifacts", run_id)
    manifest = await cl.make_async(PcapIngestor.ingest_all)(pcap_path, artifacts_dir)
    
    # 2. Indexation DB
    lake = DataLake(db_path)
    lake.reset()
    lake.ingest_manifest(manifest)
    schema = lake.get_schema()
    cl.user_session.set("schema", schema)

    # 3. Lancement Agent
    status.content = "🕵️ **Analyste Agentique au travail...**"
    await status.update()
    
    agent = build_agent()
    inputs = {
        "objective": "Analyse complète SOC (Network & System).",
        "db_path": db_path,
        "schema_info": schema,
        "iteration": 0, "max_iterations": 4, # Budget
        "sql_history": [], "evidence_items": []
    }
    
    res = await cl.make_async(agent.invoke)(inputs, config={"recursion_limit": 100})
    await status.remove()

    # 4. 🚀 LE DASHBOARD (Display)
    elements = []
    
    # A. Graphique de Réseau (HTML frame)
    graph_path = res.get("_network_graph_path") # Récupéré du state visualizer
    if graph_path and os.path.exists(graph_path):
        # Affiche le graphe interactif dans un panneau latéral ou en téléchargement
        elements.append(cl.File(name="network_graph.html", path=graph_path, display="side"))

    # B. Plotly Charts
    for k in ["timeline", "top_src", "services"]:
        fig = res.get(f"_plotly_{k}")
        if fig:
            elements.append(cl.Plotly(name=k, figure=fig, display="inline"))

    # C. Rapport Final (Markdown)
    final_md = res.get("final_answer", "Pas de conclusion.")
    
    await cl.Message(
        content=f"# 🛡️ DASHBOARD D'INVESTIGATION\n\n{final_md}\n\n---",
        elements=elements
    ).send()

    # 5. Passage en mode "Chat avec le Rapport"
    cl.user_session.set("mode", "chat")
    cl.user_session.set("context_summary", res.get("investigation_summary"))
    cl.user_session.set("context_evidence", res.get("evidence_items"))
    
    await cl.Message(content="💬 **Mode Interactif Activé.**\nPosez-moi des questions sur l'incident, je peux requêter la base pour vérifier.").send()


@cl.on_message
async def main(message: cl.Message):
    mode = cl.user_session.get("mode")
    
    if mode == "chat":
        # Mode Q&A Interactif (V2)
        db_path = cl.user_session.get("db_path")
        summary = cl.user_session.get("context_summary")
        
        # On utilise l'agent SQL "worker" pour répondre aux questions précises
        # Ou simplement un LLM RAG léger sur le résumé
        prompt = f"""
        Tu es l'assistant de l'analyste SOC.
        Contexte de l'incident : {summary}
        
        Question de l'utilisateur : {message.content}
        
        Réponds en utilisant le contexte. Si tu dois vérifier une info technique précise, 
        dis "Je dois vérifier en SQL" (fonctionnalité future).
        Pour l'instant, réponds basé sur ce que tu sais.
        """
        
        res = await cl.make_async(call_ollama)("mistral", prompt)
        await cl.Message(content=res).send()

    else:
        await cl.Message(content="⚠️ En attente d'un fichier pour démarrer l'analyse.").send()