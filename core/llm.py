import os
import json
import subprocess
import requests
from typing import Any, Dict, Optional, Union


def get_wsl_host_ip() -> str:
    """
    Récupère l'IP de l'hôte Windows via la route par défaut (WSL).
    """
    try:
        result = subprocess.run("ip route show default", shell=True, capture_output=True, text=True)
        ip = result.stdout.split()[2]
        return ip.strip()
    except Exception as e:
        print(f"⚠️ Impossible de détecter l'IP Windows via ip route: {e}")
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if "nameserver" in line:
                        return line.split()[1]
        except Exception:
            pass
    return "127.0.0.1"


if "WSL_DISTRO_NAME" in os.environ:
    host_ip = get_wsl_host_ip()
    OLLAMA_URL = f"http://{host_ip}:11434/api/generate"
    print("🔧 [LLM] Mode WSL détecté.")
    print(f"   -> Windows Host IP : {host_ip}")
    print(f"   -> Cible Ollama    : {OLLAMA_URL}")
else:
    OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


def _safe_json_loads(s: str) -> Optional[Any]:
    if not s:
        return None
    s = s.strip()
    try:
        return json.loads(s)
    except Exception:
        # fallback: sometimes models wrap in ```json ... ```
        s2 = s.replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(s2)
        except Exception:
            return None


def call_ollama(
    model: str,
    prompt: str,
    temperature: float = 0.0,
    num_ctx: int = 8192,
    timeout: int = 180,
) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": num_ctx}
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json().get("response", "")

    except requests.exceptions.ConnectTimeout:
        return f"❌ Timeout : Impossible de contacter Ollama à {OLLAMA_URL}."

    except requests.exceptions.ConnectionError:
        return (
            f"❌ **Erreur de connexion** à `{OLLAMA_URL}`.\n\n"
            "**Solutions :**\n"
            "1. Sur Windows, relancez Ollama : `ollama serve` (et `set OLLAMA_HOST=0.0.0.0`).\n"
            "2. Ouvrez le port 11434 sur le pare-feu Windows.\n"
            "3. Désactivez VPN/proxy pour tester."
        )

    except Exception as e:
        return f"❌ Erreur LLM inconnue : {str(e)}"


def call_ollama_structured(
    model: str,
    prompt: str,
    schema: Union[str, Dict[str, Any]] = "json",
    temperature: float = 0.0,
    num_ctx: int = 8192,
    timeout: int = 180,
) -> Dict[str, Any]:
    """
    Force une sortie JSON (ou JSON schema) via `format`.
    Ollama supporte `format: "json"` ou un objet JSON schema. :contentReference[oaicite:4]{index=4}
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": schema,
        "options": {"temperature": temperature, "num_ctx": num_ctx}
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    response.raise_for_status()

    txt = response.json().get("response", "")
    data = _safe_json_loads(txt)
    if isinstance(data, dict):
        return data

    # fallback: sometimes ollama returns already-parsed "response" as dict-like string issues
    raise ValueError(f"Structured output parse failed. Raw response head: {txt[:240]}")
