# Guia de Debug: Criptografia NaCl/libsodium

## Visão Geral

Este guia explica como interpretar logs de debug de sistemas que usam **crypto_box** (NaCl/libsodium) para comunicação criptografada end-to-end. O processo usa **X25519 (ECDH)** + **XSalsa20-Poly1305 (AEAD)**.

---

## Anatomia do Debug

### 🔑 Fase 1: Handshake / Acordo de Chave (Key Exchange)

```
======================================================================
[DEBUG/Box:init] <remetente> → <destinatário>
  • pub(peer): <32 bytes hex>
  • priv(self): <32 bytes hex>
  • shared_key(32B): <32 bytes hex>
======================================================================
```

#### O que cada campo significa:

| Campo | Descrição | Tamanho |
|-------|-----------|---------|
| `pub(peer)` | Chave pública do **destinatário** (Curve25519) | 32 bytes |
| `priv(self)` | Chave privada do **remetente** | 32 bytes |
| `shared_key` | Chave simétrica derivada via ECDH | 32 bytes |

#### Como funciona:

```
shared_key (K) = ECDH(priv_remetente, pub_destinatário)
```

- Ambos os lados chegam à **mesma chave K** sem transmiti-la pela rede
- O destinatário calcula: `K = ECDH(priv_destinatário, pub_remetente)`
- **K** é usada para cifrar/decifrar todas as mensagens subsequentes

> ⚠️ **Segurança**: Em produção, NUNCA logue chaves privadas ou shared_key!

---

### 🔐 Fase 2: Cifragem da Mensagem (Encryption)

```
----------------------------------------------------------------------
[DEBUG/Box:encrypt] <remetente> → <destinatário>
  • nonce(24B): <24 bytes hex>
  • plaintext(<N>B): <dados originais>
  • MAC(16B): <16 bytes hex>
  • ctext(<N>B): <dados cifrados>
  • total ciphertext(<16+N>B) = 16 + <N>
----------------------------------------------------------------------
```

#### O que cada campo significa:

| Campo | Descrição | Tamanho | Crítico? |
|-------|-----------|---------|----------|
| `nonce` | Número usado uma única vez (IV) | **24 bytes** | ✅ Jamais reutilizar! |
| `plaintext` | Dados originais antes de cifrar | N bytes | 🔒 Sensível |
| `MAC` | Tag de autenticação Poly1305 | **16 bytes** | ✅ Garante integridade |
| `ctext` | Dados cifrados com XSalsa20 | **N bytes** (mesmo que plaintext) | 🔒 Protegido |
| `total ciphertext` | MAC + ctext concatenados | **16 + N bytes** | 📦 O que vai na rede |

#### Fórmulas importantes:

```
ciphertext = plaintext ⊕ keystream(K, nonce)
MAC = Poly1305(K, nonce, ciphertext)
pacote_final = nonce || MAC || ciphertext
```

#### Cálculo do tamanho total na rede:

```
tamanho_total = 24 (nonce) + 16 (MAC) + len(plaintext)
              = 40 + len(plaintext) bytes
```

**Exemplo**: 
- Mensagem "oi" (2 bytes) → pacote de **42 bytes** (antes de Base64)
- Mensagem de 1KB (1024 bytes) → pacote de **1064 bytes**

---

### 🔓 Fase 3: Decifragem (Decryption - lado do destinatário)

```
----------------------------------------------------------------------
[DEBUG/Box:decrypt] <destinatário> recebe de <remetente>
  • nonce(24B): <extraído do pacote>
  • total_received(<16+N>B): <pacote completo>
  • MAC_verification: [PASS/FAIL]
  • plaintext(<N>B): <dados recuperados>
----------------------------------------------------------------------
```

#### Processo de decifragem:

1. **Extrai componentes do pacote**:
   ```
   nonce = primeiros 24 bytes
   MAC + ctext = restante (16+N bytes)
   ```

2. **Reconstrói a shared_key**:
   ```
   K = ECDH(priv_destinatário, pub_remetente)
   ```

3. **Verifica autenticidade**:
   ```
   MAC_calculado = Poly1305(K, nonce, ctext)
   if MAC_calculado ≠ MAC_recebido:
       ABORT! Mensagem adulterada/corrompida
   ```

4. **Decifra (se MAC passou)**:
   ```
   plaintext = ctext ⊕ keystream(K, nonce)
   ```

---

## 📊 Checklist de Validação

Use este checklist para verificar se o debug está saudável:

### ✅ Handshake (Fase 1)
- [ ] `pub(peer)` tem **exatamente 32 bytes**
- [ ] `priv(self)` tem **exatamente 32 bytes**
- [ ] `shared_key` tem **exatamente 32 bytes**
- [ ] Ambos os lados chegam à **mesma shared_key** (teste offline)

### ✅ Encryption (Fase 2)
- [ ] `nonce` tem **exatamente 24 bytes** (XSalsa20)
- [ ] `nonce` é **único** (nunca repetido com a mesma K)
- [ ] `MAC` tem **exatamente 16 bytes** (Poly1305)
- [ ] `len(ctext) == len(plaintext)` (stream cipher)
- [ ] `total_ciphertext == 16 + len(plaintext)`
- [ ] `tamanho_na_rede == 24 + 16 + len(plaintext)`

### ✅ Decryption (Fase 3)
- [ ] Pacote tem no mínimo **40 bytes** (24+16+0)
- [ ] `MAC_verification` retorna **PASS**
- [ ] `plaintext` recuperado é **idêntico** ao original
- [ ] Erros de MAC são **propagados/logados** (nunca silenciados)

---

## 🧮 Exemplos Práticos

### Exemplo 1: Mensagem "oi" (2 bytes)

```
Plaintext:  'o'=0x6f, 'i'=0x69  →  2 bytes
Nonce:      24 bytes (aleatório único)
Ctext:      2 bytes (0x520c no exemplo)
MAC:        16 bytes (Poly1305 tag)
─────────────────────────────────────
Pacote:     24 + 16 + 2 = 42 bytes
```

### Exemplo 2: Mensagem "Mensagem secreta!" (18 bytes)

```
Plaintext:  "Mensagem secreta!"  →  18 bytes
Nonce:      24 bytes (aleatório único)
Ctext:      18 bytes (XOR com keystream)
MAC:        16 bytes (Poly1305 tag)
─────────────────────────────────────
Pacote:     24 + 16 + 18 = 58 bytes
```

### Exemplo 3: Arquivo 1MB

```
Plaintext:  1.048.576 bytes (1MB)
Nonce:      24 bytes
Ctext:      1.048.576 bytes
MAC:        16 bytes
─────────────────────────────────────
Pacote:     1.048.616 bytes (~1MB + 40 bytes overhead)
Overhead:   0,0038% (desprezível)
```

---


## 🚨 Problemas Comuns e Como Detectar

### 1. Nonce Reutilizado
```
[ERRO] Dois pacotes com mesmo nonce detectados!
  • Pacote 1: nonce=452ca52e... (timestamp: 10:30:15)
  • Pacote 2: nonce=452ca52e... (timestamp: 10:30:16)
  
⚠️ CATASTRÓFICO! Permite recuperar plaintext via XOR!
```

**Solução**: Use nonce randômico (24 bytes de `/dev/urandom`) ou contador estritamente crescente.

### 2. MAC Inválido
```
[ERRO] MAC verification FAILED
  • Expected: 2310168eeff03015dd2fb147f984e9b1
  • Received: 2310168eeff03015dd2fb147f984e9b0  (1 bit diferente!)
  
❌ Mensagem corrompida ou atacada!
```

**Solução**: Rejeite a mensagem. Não tente "consertar" ou ignorar.

### 3. Tamanho Inconsistente
```
[ERRO] Tamanho do pacote não bate
  • Esperado: 24 (nonce) + 16 (MAC) + N (ctext) = X bytes
  • Recebido: Y bytes
  • Diferença: X - Y = Z bytes
```

**Solução**: Verifique serialização/desserialização do protocolo.

### 4. Shared Key Diferente
```
[ERRO] Mensagens não decifram (MAC sempre falha)
  • Possível causa: shared_key diferente em cada lado
  • Debug: Logue shared_key em AMBOS e compare offline
```

**Solução**: Verifique se as chaves públicas foram trocadas corretamente.

---

## 📚 Glossário Rápido

| Termo | Significado |
|-------|-------------|
| **ECDH** | Elliptic Curve Diffie-Hellman (acordo de chave) |
| **X25519** | Curva elíptica usada no ECDH (Curve25519) |
| **XSalsa20** | Stream cipher (cifra de fluxo) |
| **Poly1305** | MAC (Message Authentication Code) |
| **AEAD** | Authenticated Encryption with Associated Data |
| **Nonce** | Number used ONCE (IV, mas não precisa ser secreto) |
| **MAC** | Garante integridade + autenticidade |
| **Keystream** | Sequência pseudoaleatória do XSalsa20 |
| **K** | Shared key (chave de sessão) |

---

## 🎯 Resumo: O que olhar nos logs

1. **Handshake**: Confirme que `shared_key` tem 32B
2. **Encrypt**: 
   - Nonce único (24B)
   - Total = 40 + len(plaintext)
3. **Decrypt**: MAC verification deve ser **PASS**
4. **Regra de ouro**: `len(ctext) == len(plaintext)` sempre!

---

## 🔗 Referências

- [NaCl: Networking and Cryptography library](https://nacl.cr.yp.to/)
- [libsodium documentation](https://doc.libsodium.org/)
- [RFC 7748 - X25519](https://tools.ietf.org/html/rfc7748)
- [XSalsa20 spec](https://cr.yp.to/snuffle/xsalsa-20110204.pdf)

---

**Última atualização**: Novembro 2025  
**Autor**: Baseado em análise de logs reais de produção