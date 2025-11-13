"""
Módulo de persistência para salvar e carregar conversas e grupos
"""

import json
from pathlib import Path


def get_state_file(client_id: str) -> Path:
    """Retorna o caminho do arquivo de estado para um cliente."""
    return Path(f"{client_id}_state.json")


def save_conversations(client_id: str, conversations: dict):
    """Salva o estado das conversas em arquivo JSON."""
    try:
        state_file = get_state_file(client_id)
        # Converter tuplas em listas para JSON
        serializable = {}
        for conv_id, conv_data in conversations.items():
            serializable[conv_id] = {
                "type": conv_data.get("type", "private"),
                "key": conv_data.get("key"),
                "history": [
                    {"timestamp": ts, "sender": sender, "message": msg}
                    for ts, sender, msg in conv_data.get("history", [])
                ],
            }
            # Se houver chave de grupo, converter para base64
            if serializable[conv_id]["key"]:
                import base64

                serializable[conv_id]["key"] = base64.b64encode(
                    serializable[conv_id]["key"]
                ).decode()

        with state_file.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Erro ao salvar estado: {e}")


def load_conversations(client_id: str) -> dict:
    """Carrega o estado das conversas de arquivo JSON."""
    try:
        state_file = get_state_file(client_id)
        if not state_file.exists():
            return {}

        with state_file.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Converter de volta para o formato interno
        conversations = {}
        for conv_id, conv_data in data.items():
            conversations[conv_id] = {
                "type": conv_data.get("type", "private"),
                "key": None,
                "history": [],
            }

            # Restaurar chave de grupo se existir
            if conv_data.get("key"):
                import base64

                conversations[conv_id]["key"] = base64.b64decode(
                    conv_data["key"].encode()
                )

            # Restaurar histórico
            for msg in conv_data.get("history", []):
                conversations[conv_id]["history"].append(
                    (msg["timestamp"], msg["sender"], msg["message"])
                )

        return conversations
    except Exception as e:
        print(f"Erro ao carregar estado: {e}")
        return {}
