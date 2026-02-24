# 🔐 Mesh-ERL Protocol — Aegis Ratchet v1

<div align="center">

![Erlang](https://img.shields.io/badge/Erlang-OTP_25%2B-8A2BE2?style=for-the-badge&logo=erlang&logoColor=white)
![Crypto Suite](https://img.shields.io/badge/Crypto-X25519_·_HKDF_SHA256_·_AES_256_GCM-0A7EA4?style=for-the-badge&logo=letsencrypt&logoColor=white)
![Security Model](https://img.shields.io/badge/Security-Forward_Secrecy_+_Replay_Protection-1F9D55?style=for-the-badge&logo=shield&logoColor=white)
![Implementation](https://img.shields.io/badge/Implementation-Erlang_Prototype-FF6B6B?style=for-the-badge&logo=elixir&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-111827?style=for-the-badge)

</div>

> ⚠️ **Важно:** это инженерный прототип. Он сильно усложняет стандартные атаки перехвата и подмены, но «абсолютно невзламываемых» протоколов не бывает.

---

## 🚀 Что здесь «революционного»

`Aegis Ratchet v1` сочетает в себе несколько защитных слоев сразу:

1. **Triple-DH рукопожатие (X25519)** — смешивание нескольких ECDH секретов.
2. **HKDF-SHA256** — стабильный вывод root/chain ключей.
3. **Message Key на каждый пакет** — отдельный ключ для каждого сообщения.
4. **AES-256-GCM (AEAD)** — шифрование + контроль целостности.
5. **AAD-привязка заголовка** — попытка изменить метаданные ломает верификацию.
6. **Ratchet-прогрессия** — компрометация «сейчас» не раскрывает всё «потом/раньше».

---

## 🧠 Архитектура протокола

> Ниже схема переписана в GitHub-compatible Mermaid синтаксисе (без проблемных токенов).

```mermaid
flowchart LR
    A["Alice: IK_A + EK_A"] -->|"Init packet"| B["Bob: IK_B + OPK_B"]
    B -->|"Response + ack"| A

    subgraph HS["Handshake Secret Mix"]
      D1["DH1 = ECDH EK_A · IK_B"]
      D2["DH2 = ECDH IK_A · OPK_B"]
      D3["DH3 = ECDH EK_A · OPK_B"]
      KDF["HKDF SHA256"]
      D1 --> KDF
      D2 --> KDF
      D3 --> KDF
    end

    KDF --> RK["Root Key"]
    RK --> CKs["Send Chain Key"]
    RK --> CKr["Recv Chain Key"]
```

---

## 📨 Поток одного сообщения

```mermaid
sequenceDiagram
    participant S as Sender
    participant N as Network / Attacker
    participant R as Receiver

    S->>S: derive message_key from chain_key + counter
    S->>S: derive next_chain_key
    S->>S: nonce = random 96-bit
    S->>N: header + AEAD ciphertext + tag
    N-->>R: forward or tamper attempt
    R->>R: derive same message_key
    R->>R: verify tag with header as AAD
    R->>R: decrypt or reject
```

---

## 🛡️ Во что «упирается» атака

```mermaid
flowchart TD
    X["Attacker intercepts traffic"] --> Y{"Attack type"}

    Y --> P["Passive sniffing"]
    P --> P1["Sees only ciphertext, nonce, counter"]
    P1 --> P2["No shared secret => no message key"]

    Y --> M["Tampering / MITM"]
    M --> M1["Changes header or ciphertext"]
    M1 --> M2["AEAD tag check fails because AAD bound"]

    Y --> R["Replay"]
    R --> R1["Resends old packet"]
    R1 --> R2["Counter already used => reject"]

    Y --> K["Current key compromise"]
    K --> K1["Damage limited in time window"]
    K1 --> K2["Ratchet progression reduces blast radius"]
```

---

## ⚙️ Практическая реализация

- Протокол: `src/mesh_aegis.erl`
- Демо: `src/mesh_demo.erl`

### Реализовано

- Генерация identity и ephemeral ключей на `X25519`.
- Triple-DH handshake + HKDF key schedule.
- Отдельные send/recv chain keys.
- AEAD шифрование `AES-256-GCM`.
- Replay защита через монотонный counter.
- Аутентификация заголовка через AAD.

---

## ▶️ Быстрый запуск

```bash
erlc -o ebin src/mesh_aegis.erl src/mesh_demo.erl
erl -pa ebin -noshell -s mesh_demo run -s init stop
```

Ожидаемо в выводе:

- `Handshake complete.`
- `Tampering attack blocked ...`
- `Replay attack blocked.`
- Успешная двусторонняя расшифровка сообщений.

---

## 🔬 Криптографический стек

- **ECDH:** X25519
- **KDF:** HKDF-SHA256
- **AEAD:** AES-256-GCM
- **Ratchet progression:** HMAC-SHA256

---

## ⚠️ Ограничения прототипа

- Нет production-grade identity verification (подписи/pinning).
- Нет полного механизма хранения пропущенных message keys (как в полном Double Ratchet).
- Нет formal verification и внешнего аудита.

---

## ✅ Что добавить до production

1. Ed25519 подписи identity-ключей + pinning/TOFU.
2. Hybrid secret mix (например, + post-quantum KEM).
3. Session lifecycle: expiration, rekey, revocation.
4. Внешний security audit + threat-model review.

