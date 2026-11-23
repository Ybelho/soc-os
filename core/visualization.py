import os
import networkx as nx
from pyvis.network import Network
import pandas as pd
import plotly.express as px
from core.datalake import DataLake

CHARTS_DIR = "public/charts"
os.makedirs(CHARTS_DIR, exist_ok=True)

class Visualizer:
    def __init__(self, db_path: str):
        self.lake = DataLake(db_path)

    def generate_network_graph(self) -> str:
        """Génère un graphe de relations IP interactif (HTML)"""
        try:
            # On prend les Top 200 conversations pour ne pas faire exploser le navigateur
            q = """
                SELECT src_ip, dst_ip, COUNT(*) as weight 
                FROM events 
                WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL 
                GROUP BY 1, 2 
                ORDER BY 3 DESC 
                LIMIT 200
            """
            df = self.lake.con.execute(q).df()
            if df.empty: return None

            G = nx.from_pandas_edgelist(df, 'src_ip', 'dst_ip', edge_attr='weight')

            # Pyvis pour l'interactivité
            net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
            net.from_nx(G)
            
            # Options physiques pour que ça bouge bien ("Arkime style")
            net.repulsion(node_distance=150, spring_length=200)
            
            out_path = os.path.join(CHARTS_DIR, "network_graph.html")
            net.save_graph(out_path)
            return out_path
        except Exception as e:
            print(f"Graph Error: {e}")
            return None

    def generate_plotly_objects(self) -> dict:
        """Retourne un dictionnaire de Figures Plotly"""
        dfs = {}
        figs = {}
        
        queries = {
            "timeline": "SELECT date_trunc('minute', timestamp) AS time, COUNT(*) AS volume FROM events GROUP BY 1 ORDER BY 1",
            "top_src": "SELECT src_ip, COUNT(*) AS volume FROM events WHERE src_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15",
            "services": "SELECT service, COUNT(*) AS volume FROM events WHERE service IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15"
        }

        for key, sql in queries.items():
            try:
                dfs[key] = self.lake.con.execute(sql).df()
            except: pass

        # Timeline
        if "timeline" in dfs and not dfs["timeline"].empty:
            fig = px.area(dfs["timeline"], x="time", y="volume", title="Chronologie du Trafic", template="plotly_dark")
            figs["timeline"] = fig

        # Sankey ou Bar pour les IPs
        if "top_src" in dfs and not dfs["top_src"].empty:
            fig = px.bar(dfs["top_src"], x="src_ip", y="volume", title="Top Sources", template="plotly_dark", color="volume")
            figs["top_src"] = fig
            
        return figs