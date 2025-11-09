
import argparse
import asyncio
import base64
import json
import os
import ssl
import time
import logging

from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logger = logging.getLogger("chatseguro.client")

def setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )

# -------------------------------------------------------------------
# Util
# -------------------------------------------------------------------
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def short_b64(x: bytes, n=10) -> str:
    try:
        return b64(x)[:n] + "..."
    except Exception:
        return "<na>"

def hex_preview(data: bytes, length=16) -> str:
    """Mostra preview em hexadecimal dos primeiros bytes"""
    return data[:length].hex() + ("..." if len(data) > length else "")

class TLSSocketClient:
    def __init__(self, host, port, cafile=None, debug=False):
        self.host = host
        self.port = port
        self.cafile = cafile
        self.debug = debug

    async def send_recv(self, obj):
        try:
            sslctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.cafile:
                sslctx.load_verify_locations(self.cafile)
                if self.debug:
                    logger.debug("")
                    logger.debug("[client.py][TLS] Conectando ao servidor com verificação de certificado")
                    logger.debug("  └─ Arquivo: client.py | Classe: TLSSocketClient | Método: send_recv()")
                    logger.debug("  └─ CA Certificate: %s", self.cafile)
            else:
                # APENAS PARA DESENVOLVIMENTO
                sslctx.check_hostname = False
                sslctx.verify_mode = ssl.CERT_NONE
                if self.debug:
                    logger.debug("")
                    logger.debug("[client.py][TLS] Conectando ao servidor SEM verificação (DEV ONLY)")
                    logger.debug("  └─ Arquivo: client.py | Classe: TLSSocketClient | Método: send_recv()")
                    logger.debug("  └─ ⚠️  ATENÇÃO: Modo inseguro! Vulnerável a MITM!")

            reader, writer = await asyncio.open_connection(self.host, self.port, ssl=sslctx)

            payload = (json.dumps(obj)+"\n").encode()
            writer.write(payload)
            await writer.drain()

            line = await reader.readline()

            writer.close()
            await writer.wait_closed()

            if not line:
                return {"status": "error", "reason": "Nenhuma resposta recebida do servidor."}

            return json.loads(line.decode())
        except json.JSONDecodeError:
            return {"status": "error", "reason": "O servidor enviou uma resposta inválida."}
        except ConnectionRefusedError:
            return {"status": "error", "reason": "A conexão foi recusada. O servidor está offline?"}
        except Exception as e:
            return {"status": "error", "reason": f"Erro de conexão: {e}"}

async def interactive(server_host, server_port, cacert, client_id, debug):
    setup_logging(debug)
    client_id = client_id.strip().strip('"')
    client = TLSSocketClient(server_host, server_port, cacert, debug)

    logger.info("")
    logger.info("=" * 70)
    logger.info("[client.py][KEYGEN] Gerando par de chaves para o cliente")
    logger.info("  └─ Arquivo: client.py | Função: interactive()")
    logger.info("  └─ Cliente ID: %s", client_id)
    logger.info("  └─ Algoritmo: Curve25519 (ECDH - Elliptic Curve Diffie-Hellman)")
    logger.info("  └─ Biblioteca: PyNaCl (libsodium)")

    priv = PrivateKey.generate()
    pub = bytes(priv.public_key)

    logger.info("  └─ ✅ Chave privada: %d bytes", len(bytes(priv)))
    logger.info("  └─ ✅ Chave pública: %d bytes", len(pub))
    logger.info("  └─ Chave pública (hex): %s", hex_preview(pub))
    logger.info("  └─ Chave pública (base64): %s", short_b64(pub, 20))
    logger.info("=" * 70)

    # PUBLICA CHAVE
    logger.info("")
    logger.info("[client.py][PUBKEY_PUBLISH] Publicando chave pública no servidor")
    logger.info("  └─ Arquivo: client.py | Função: interactive()")

    resp = await client.send_recv(
        {"type": "publish_key", "client_id": client_id, "pubkey": b64(pub)}
    )
    if resp.get("status") != "ok":
        print("❌ Erro ao publicar chave:", resp)
        return

    logger.info("  └─ ✅ Chave publicada com sucesso!")
    print(f"✅ Conectado como: {client_id}")

    conversations = {}  # peer_id -> [ (timestamp, sender, mensagem) ]
    groups = {}         # group_id -> { "key": bytes, "history": [] }
    new_msgs = {}       # peer_id -> int (novas mensagens)

    async def ainput(prompt=""):
        return await asyncio.to_thread(input, prompt)

    async def poll_blobs():
        while True:
            try:
                response = await client.send_recv(
                    {"type": "fetch_blobs", "client_id": client_id}
                )
                if response.get("status") == "ok":
                    for m in response.get("messages", []):
                        if m.get("type") == "group":
                            group_id = m["group_id"]
                            if group_id not in groups:
                                groups[group_id] = {"key": None, "history": []}

                            raw = ub64(m["blob"])
                            nonce = raw[:SecretBox.NONCE_SIZE]
                            ct = raw[SecretBox.NONCE_SIZE:]

                            logger.debug("")
                            logger.debug("[client.py][RECV][GRUPO] Mensagem de grupo recebida (cifrada)")
                            logger.debug("  └─ Arquivo: client.py | Função: poll_blobs()")
                            logger.debug("  └─ Grupo: %s", group_id)
                            logger.debug("  └─ Remetente: %s", m["from"])
                            logger.debug("  └─ Algoritmo: XSalsa20-Poly1305 (AEAD)")
                            logger.debug("  └─ Nonce: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                            logger.debug("  └─ Ciphertext: %d bytes (inclui 16 bytes de MAC Poly1305)", len(ct))
                            logger.debug("  └─ Status: Aguardando descriptografia pelo destinatário")

                            groups[group_id]["history"].append(("received_group", m))
                            new_msgs[group_id] = new_msgs.get(group_id, 0) + 1
                        else:
                            # Pode ser distribuição de chave de grupo
                            try:
                                env = json.loads(base64.b64decode(m["blob"]).decode())
                                if env.get("type") == "group_key_distribution":
                                    logger.debug("")
                                    logger.debug("[client.py][RECV] Distribuição de chave de grupo")
                                    logger.debug("  └─ Arquivo: client.py | Função: poll_blobs()")

                                    peer_pub_b64 = env["sender_pub"]
                                    peer_pub = PublicKey(ub64(peer_pub_b64))
                                    box = Box(priv, peer_pub)

                                    key_blob_combined = ub64(env["key_blob"])
                                    nonce = key_blob_combined[:Box.NONCE_SIZE]
                                    ct = key_blob_combined[Box.NONCE_SIZE:]

                                    logger.debug("  └─ Algoritmo: NaCl Box (X25519 + XSalsa20-Poly1305)")
                                    logger.debug("  └─ Nonce: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                                    logger.debug("  └─ Ciphertext: %d bytes", len(ct))
                                    logger.debug("  └─ Descriptografando chave simétrica do grupo...")

                                    group_key = box.decrypt(key_blob_combined)
                                    group_id = env["group_id"]

                                    if group_id not in groups:
                                        groups[group_id] = {"history": []}
                                    groups[group_id]["key"] = group_key

                                    logger.debug("  └─ ✅ Chave de grupo obtida: %d bytes", len(group_key))
                                    logger.debug("  └─ Grupo ID: %s", group_id)
                                    logger.debug("  └─ Esta chave será usada para criptografia simétrica no grupo")

                                    print(f"\n🔑 Você foi adicionado ao grupo '{group_id}' e recebeu a chave simétrica.")
                                    continue
                            except Exception as e:
                                logger.debug("Envelope não era chave de grupo: %s", e)

                            # Mensagem privada (cifrada) recebida
                            peer = m["from"]
                            raw = base64.b64decode(m["blob"])
                            try:
                                env = json.loads(raw.decode())
                                blob_combined = ub64(env["blob"])
                                nonce = blob_combined[:Box.NONCE_SIZE]
                                ct = blob_combined[Box.NONCE_SIZE:]

                                logger.debug("")
                                logger.debug("[client.py][RECV][PRIVADA] Mensagem privada recebida (cifrada)")
                                logger.debug("  └─ Arquivo: client.py | Função: poll_blobs()")
                                logger.debug("  └─ Remetente: %s", peer)
                                logger.debug("  └─ Algoritmo: NaCl Box (X25519 + XSalsa20-Poly1305)")
                                logger.debug("  └─ Nonce: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                                logger.debug("  └─ Ciphertext: %d bytes (inclui 16 bytes de MAC Poly1305)", len(ct))
                                logger.debug("  └─ Status: Aguardando descriptografia pelo destinatário")
                            except Exception:
                                pass

                            if peer not in conversations:
                                conversations[peer] = []
                            conversations[peer].append(("received", m))
                            new_msgs[peer] = new_msgs.get(peer, 0) + 1
            except Exception as e:
                logger.error("Erro no polling: %s", e)
            await asyncio.sleep(1)

    poll_task = asyncio.create_task(poll_blobs())

    def show_menu():
        print("\n" + "=" * 70)
        print("📋 COMANDOS DISPONÍVEIS")
        print("=" * 70)
        print("  • Listar                        → Mostra usuários e grupos")
        print("  • Iniciar chat <cliente>        → Inicia conversa privada")
        print("  • Criar grupo <nome> com <...>  → Cria grupo com membros")
        print("  • Conversas                     → Entra em chats ativos")
        print("  • Sair                          → Encerra o cliente")
        print("=" * 70)

    show_menu()

    while True:
        line = await ainput("\n>> ")
        if not line:
            continue
        parts = line.strip().split(" ", 3)
        cmd = parts[0].lower()

        if cmd=="listar":
            try:
                resp = await client.send_recv({"type":"list_all","client_id":client_id})
                if resp.get("status")=="ok":
                    print("\n👥 Clientes disponíveis:", resp.get("clients",[]))
                    print("👨‍👩‍👧‍👦 Grupos disponíveis:", resp.get("groups",[]))
                else:
                    print(f"❌ Erro ao listar: {resp.get('reason', 'causa desconhecida')}")
            except Exception as e:
                print("❌ Erro:", e)

        elif cmd == "criar" and len(parts) > 1 and parts[1].lower() == "grupo":
            # parsing de múltiplos membros
            try:
                full_command_parts = line.strip().split()
                group_id = full_command_parts[2]
                com_index = full_command_parts.index("com")
                members = full_command_parts[com_index + 1:]

                if not members:
                    print("❌ Erro: Você precisa especificar pelo menos um membro.")
                    continue

                members.append(client_id)

            except (ValueError, IndexError):
                print("❌ Formato inválido. Use: criar grupo <nome> com <membro1> <membro2>...")
                continue

            logger.info("")
            logger.info("[client.py][KEYGEN][GRUPO] Gerando chave simétrica para o grupo")
            logger.info("  └─ Arquivo: client.py | Função: interactive() | Comando: criar grupo")
            logger.info("  └─ Grupo ID: %s", group_id)
            logger.info("  └─ Algoritmo: XSalsa20-Poly1305 (AEAD)")
            logger.info("  └─ Tamanho da chave: %d bytes", SecretBox.KEY_SIZE)

            # gerar chave simétrica do grupo
            group_key = os.urandom(SecretBox.KEY_SIZE)

            logger.info("  └─ ✅ Chave gerada: %s", hex_preview(group_key))
            logger.info("  └─ Esta chave será compartilhada criptografada com todos os membros")

            groups[group_id] = {"key": group_key, "history": []}

            # criar grupo no servidor
            await client.send_recv(
                {"type": "create_group", "group_id": group_id, "members": members, "admin": client_id}
            )

            # distribuir a chave
            print(f"\n🔐 Distribuindo chave criptografada para {len(members)-1} membro(s)...")

            for member in members:
                if member == client_id:
                    continue

                # obter chave pública do membro
                resp = await client.send_recv({"type": "get_key", "client_id": member})
                if resp.get("status") != "ok":
                    print(f"  ❌ Erro ao obter chave de {member}: {resp.get('reason')}")
                    continue

                peer_pub = PublicKey(ub64(resp["pubkey"]))
                box = Box(priv, peer_pub)

                logger.debug("")
                logger.debug("[client.py][ENCRYPT] Criptografando chave de grupo para membro")
                logger.debug("  └─ Arquivo: client.py | Função: interactive() | Lógica: distribuir_chave_grupo")
                logger.debug("  └─ Destinatário: %s", member)
                logger.debug("  └─ Algoritmo: NaCl Box (X25519 + XSalsa20-Poly1305)")
                logger.debug("  └─ Plaintext: Chave simétrica do grupo (%d bytes)", len(group_key))

                # cifrar a chave do grupo para o membro
                enc = box.encrypt(group_key)
                nonce, ct = enc.nonce, enc.ciphertext

                logger.debug("  └─ Nonce gerado: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                logger.debug("  └─ Ciphertext: %d bytes (chave + 16 bytes de MAC Poly1305)", len(ct))
                logger.debug("  └─ ✅ Chave cifrada com sucesso para %s", member)

                envelope = {
                    "type": "group_key_distribution",
                    "group_id": group_id,
                    "sender_pub": b64(pub),
                    "key_blob": b64(bytes(enc)),
                }
                payload = {
                    "type": "send_blob",
                    "to": member,
                    "from": client_id,
                    "blob": b64(json.dumps(envelope).encode()),
                }
                await client.send_recv(payload)
                print(f"  ✅ Chave enviada para {member}")

            print(f"\n✅ Grupo '{group_id}' criado com sucesso!")

        elif cmd == "conversas":
            active_convs = list(conversations.keys()) + list(groups.keys())
            if not active_convs:
                print("\n📭 Nenhuma conversa ativa.")
                continue

            print("\n💬 Conversas ativas:")
            for peer in active_convs:
                count = new_msgs.get(peer, 0)
                msg_info = f" ({count} novas)" if count else ""
                conv_type = "🏘️ [grupo]" if peer in groups else "👤 [privado]"
                print(f"  • {peer}{msg_info} {conv_type}")

            peer_choice = (await ainput("\nEntrar em qual conversa (ou Enter para voltar)? ")).strip()
            if not peer_choice or peer_choice not in active_convs:
                continue

            peer = peer_choice
            new_msgs[peer] = 0

            # ------------------------- Grupo -------------------------
            if peer in groups:
                group = groups[peer]
                if not group.get("key"):
                    print("⏳ Aguardando recebimento da chave deste grupo...")
                    continue

                group_box = SecretBox(group["key"])
                print(f"\n{'=' * 70}")
                print(f"💬 Conversa em Grupo: {peer}")
                print(f"{'=' * 70}")
                print("Digite /quit para sair\n")

                # histórico
                for entry in group["history"]:
                    ts = time.strftime("%H:%M:%S")
                    if entry[0] == "received_group":
                        m = entry[1]
                        raw = ub64(m["blob"])
                        nonce = raw[:SecretBox.NONCE_SIZE]
                        ct = raw[SecretBox.NONCE_SIZE:]

                        logger.debug("")
                        logger.debug("[client.py][DECRYPT][GRUPO] Descriptografando mensagem de grupo")
                        logger.debug("  └─ Arquivo: client.py | Função: interactive() | Lógica: exibir_historico_grupo")
                        logger.debug("  └─ Remetente: %s", m['from'])
                        logger.debug("  └─ Algoritmo: XSalsa20-Poly1305 (SecretBox)")
                        logger.debug("  └─ Nonce: %s", hex_preview(nonce))
                        logger.debug("  └─ Ciphertext: %d bytes", len(ct))

                        try:
                            pt = group_box.decrypt(raw)
                            logger.debug("  └─ ✅ Descriptografia bem-sucedida")
                            logger.debug("  └─ Plaintext: %d bytes | Preview: %s", len(pt), pt[:30])
                            print(f"[{ts}] {m['from']}: {pt.decode()}")
                        except Exception as e:
                            logger.debug("  └─ ❌ Falha na descriptografia: %s", e)
                            print(f"[{ts}] {m['from']}: <erro ao decifrar>")
                    else:
                        ts, sender, msg = entry
                        print(f"[{ts}] {sender}: {msg}")

                # loop do chat
                while True:
                    text = await ainput("")
                    if text.strip() == "/quit":
                        print(f"👋 Saindo da conversa com {peer}.\n")
                        break

                    ts = time.strftime("%H:%M:%S")

                    logger.debug("")
                    logger.debug("[client.py][ENCRYPT][GRUPO] Criptografando mensagem para grupo")
                    logger.debug("  └─ Arquivo: client.py | Função: interactive() | Lógica: enviar_msg_grupo")
                    logger.debug("  └─ Grupo: %s", peer)
                    logger.debug("  └─ Algoritmo: XSalsa20-Poly1305 (SecretBox)")
                    logger.debug("  └─ Plaintext: %d bytes", len(text.encode()))

                    enc = group_box.encrypt(text.encode())
                    nonce, ct = enc.nonce, enc.ciphertext

                    logger.debug("  └─ Nonce gerado: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                    logger.debug("  └─ Ciphertext: %d bytes (msg + 16 bytes MAC)", len(ct))
                    logger.debug("  └─ ✅ Mensagem criptografada com sucesso")

                    payload = {
                        "type": "send_group_blob",
                        "group_id": peer,
                        "from": client_id,
                        "blob": b64(bytes(enc)),
                    }
                    await client.send_recv(payload)
                    group["history"].append((ts, client_id, text))
                    print(f"[{ts}] {client_id}: {text}")
                continue

            # ------------------------- Privado -------------------------
            resp = await client.send_recv({"type": "get_key", "client_id": peer})
            if resp.get("status") != "ok":
                print("❌ Não foi possível obter chave do peer:", resp)
                continue

            peer_pub = PublicKey(ub64(resp["pubkey"]))
            box = Box(priv, peer_pub)

            print(f"\n{'=' * 70}")
            print(f"💬 Conversa Privada com: {peer}")
            print(f"{'=' * 70}")
            print("Digite /quit para sair\n")

            for entry in conversations[peer]:
                ts = time.strftime("%H:%M:%S")
                if entry[0] == "received":
                    m = entry[1]
                    env = json.loads(base64.b64decode(m["blob"]).decode())
                    blob_combined = ub64(env["blob"])
                    nonce = blob_combined[:Box.NONCE_SIZE]
                    ct = blob_combined[Box.NONCE_SIZE:]

                    logger.debug("")
                    logger.debug("[client.py][DECRYPT][PRIVADA] Descriptografando mensagem privada")
                    logger.debug("  └─ Arquivo: client.py | Função: interactive() | Lógica: exibir_historico_privado")
                    logger.debug("  └─ Remetente: %s", m['from'])
                    logger.debug("  └─ Algoritmo: NaCl Box (X25519 + XSalsa20-Poly1305)")
                    logger.debug("  └─ Nonce: %s", hex_preview(nonce))
                    logger.debug("  └─ Ciphertext: %d bytes", len(ct))

                    sender_pub = PublicKey(ub64(env["sender_pub"]))
                    msg_box = Box(priv, sender_pub)
                    try:
                        pt = msg_box.decrypt(blob_combined)
                        logger.debug("  └─ ✅ Descriptografia bem-sucedida")
                        logger.debug("  └─ Plaintext: %d bytes", len(pt))
                        print(f"[{ts}] {m['from']}: {pt.decode()}")
                    except Exception as e:
                        logger.debug("  └─ ❌ Falha na descriptografia: %s", e)
                        print(f"[{ts}] {m['from']}: <erro ao decifrar>")
                else:
                    ts, sender, msg = entry
                    print(f"[{ts}] {sender}: {msg}")

            while True:
                text = await ainput("")
                if text.strip() == "/quit":
                    print(f"👋 Saindo da conversa com {peer}.\n")
                    break

                ts = time.strftime("%H:%M:%S")

                logger.debug("")
                logger.debug("[client.py][ENCRYPT][PRIVADA] Criptografando mensagem privada")
                logger.debug("  └─ Arquivo: client.py | Função: interactive() | Lógica: enviar_msg_privada")
                logger.debug("  └─ Destinatário: %s", peer)
                logger.debug("  └─ Algoritmo: NaCl Box (X25519 + XSalsa20-Poly1305)")
                logger.debug("  └─ Plaintext: %d bytes", len(text.encode()))

                enc = box.encrypt(text.encode())
                nonce, ct = enc.nonce, enc.ciphertext

                logger.debug("  └─ Nonce gerado: %d bytes | Hex: %s", len(nonce), hex_preview(nonce))
                logger.debug("  └─ Ciphertext: %d bytes (msg + 16 bytes MAC)", len(ct))
                logger.debug("  └─ ✅ Mensagem criptografada com sucesso")

                envelope = {"sender_pub": b64(pub), "blob": b64(bytes(enc))}
                payload = {
                    "type": "send_blob",
                    "to": peer,
                    "from": client_id,
                    "blob": b64(json.dumps(envelope).encode()),
                }
                await client.send_recv(payload)
                conversations[peer].append((ts, client_id, text))
                print(f"[{ts}] {client_id}: {text}")

        elif cmd == "iniciar":
            if len(parts) < 3 or parts[1].lower() != "chat":
                print("❌ Uso: Iniciar chat <cliente>")
                continue
            peer = parts[2].strip().strip('"')
            if peer == client_id:
                print("❌ Não é possível iniciar chat consigo mesmo.")
                continue
            if peer not in conversations:
                conversations[peer] = []
            print(f"✅ Conversa com {peer} criada. Use 'Conversas' para entrar nela.")

        elif cmd == "sair":
            print("\n👋 Encerrando cliente...")
            poll_task.cancel()
            break
        else:
            print("❌ Comando desconhecido.")
            show_menu()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Cliente de Chat Seguro - Projeto de Segurança da Informação")
    p.add_argument("--server", required=True, help="Endereço do servidor (host:port)")
    p.add_argument("--cacert", help="Certificado CA para verificação TLS")
    p.add_argument("--id", required=True, help="ID do cliente")
    p.add_argument("--debug", action="store_true", help="Ativa logs detalhados de criptografia e hash")
    args = p.parse_args()

    print("\n" + "=" * 70)
    print("🔐 CHAT SEGURO - Cliente de Mensagens Criptografadas")
    print("=" * 70)
    print("📚 Projeto: Segurança da Informação")
    print("🔒 Algoritmos:")
    print("   • X25519 (ECDH) - Troca de chaves")
    print("   • XSalsa20 - Cifragem de fluxo")
    print("   • Poly1305 - Autenticação de mensagem (MAC)")
    print("   • SHA-256 - Hash para certificados TLS")
    print("=" * 70)

    if args.debug:
        print("🐛 Modo DEBUG ativado - Logs detalhados de criptografia")
        print("=" * 70)

    host, port = args.server.split(":")
    asyncio.run(interactive(host, int(port), args.cacert, args.id, args.debug))