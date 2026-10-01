<!-- markdownlint-disable MD033 -->
# 🔐 Secure DB API — Projeto Acadêmico de Segurança em Banco de Dados

Sistema demonstrando **4 mecanismos de segurança** em uma arquitetura FastAPI + PostgreSQL, orquestrada via Docker Compose.

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network: secure_net            │
│                                                          │
│   ┌──────────────────┐       ┌─────────────────────┐    │
│   │   FastAPI API    │──────▶│   PostgreSQL 16      │    │
│   │  (porta 8000)    │       │   (porta 5432)       │    │
│   │                  │       │                      │    │
│   │  • crypto.py     │       │  • RLS Policies      │    │
│   │  • auth.py       │       │  • Audit Triggers    │    │
│   │  • database.py   │       │  • Masked View       │    │
│   └──────────────────┘       └─────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## 🔒 Os 4 Mecanismos de Segurança

### 1️⃣ Envelope Encryption (AES-256-GCM)
**Arquivo:** `app/crypto.py`

```
KEK (Key Encryption Key)  ←── variável de ambiente KEK_HEX
 └── protege a DEK (Data Encryption Key)  ←── gerada aleatoriamente por registro
      └── cifra CPF e valor financeiro com AES-256-GCM
```

- Cada registro tem sua própria DEK de 256 bits
- A DEK cifrada é armazenada junto ao ciphertext no banco
- Rotação de chave = apenas re-cifrar as DEKs com nova KEK

### 2️⃣ Row-Level Security (RLS)
**Arquivo:** `init.sql` (seção 4) + `app/database.py`

- Política `tenant_isolation_policy` no PostgreSQL
- A API injeta: `SET LOCAL app.current_user_id = '<uuid>'`
- **Sem WHERE no código Python** — o banco filtra automaticamente
- `FORCE ROW LEVEL SECURITY` garante que até o owner da tabela está sujeito às políticas

### 3️⃣ Audit Trail com Hash Chaining
**Arquivo:** `init.sql` (seção 5) + `app/routers/audit_router.py`

```
Entry #1: hash = SHA256("dados1" + "GENESIS")
Entry #2: hash = SHA256("dados2" + hash_entry_1)
Entry #3: hash = SHA256("dados3" + hash_entry_2)
   ↑ adulteração em qualquer entrada invalida todas as subsequentes
```

- Trigger `trg_financial_audit` dispara em INSERT/UPDATE/DELETE
- Função `verify_audit_chain()` valida toda a cadeia

### 4️⃣ RBAC + Dynamic Data Masking
**Arquivo:** `init.sql` (seções 2 e 6)

- `api_user` tem apenas permissões DML (SELECT, INSERT, UPDATE, DELETE)
- **Sem DDL** (CREATE, DROP, ALTER) — menor privilégio
- View `financial_records_masked` mascara nome e CPF no nível do banco

---

## 🚀 Como Executar

### Pré-requisitos
- Docker Desktop instalado e rodando
- Docker Compose v2+

### Inicialização
```bash
# Clone ou navegue até o diretório do projeto
cd Back-End-banco-de-dados

# Suba todos os serviços (banco + API)
docker compose up -d

# Verifique os logs
docker compose logs -f

# Aguarde a mensagem "Application startup complete" da API
```

### Acesso
| Serviço | URL |
|---------|-----|
| Swagger UI (teste interativo) | http://localhost:8000/docs |
| ReDoc (documentação) | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |
| PostgreSQL | localhost:5432 |

---

## 🧪 Roteiro de Testes dos 4 Mecanismos

Acesse **http://localhost:8000/docs** e siga:

### Teste 1 — Envelope Encryption
1. `POST /auth/register` → crie usuário `alice` / `senha12345`
2. `POST /auth/login` → obtenha o token
3. Clique em **Authorize** → cole o token
4. `POST /records` → crie um registro com CPF e valor
5. Conecte-se ao banco: `docker exec -it secure_db psql -U postgres -d securedb`
6. `SELECT cpf_enc, valor_enc, dek_enc FROM financial_records;`
7. **Observe:** os dados aparecem como base64 cifrado — indecifráveis sem a KEK

### Teste 2 — Row-Level Security
1. Com `alice` logada, crie 2 registros
2. `POST /auth/register` → crie usuário `bob` / `senha12345`
3. Faça login como `bob` e use o novo token
4. `GET /records` → **Bob não verá nenhum registro de Alice**
5. Tente `GET /records/{id_de_alice}` → 404 (RLS bloqueia silenciosamente)

### Teste 3 — Audit Hash Chain
1. Execute algumas operações (INSERT, UPDATE, DELETE)
2. `GET /audit/logs` → veja os logs com `row_hash` e `prev_hash`
3. `GET /audit/verify` → todos `is_valid: true` ✅
4. **Simule adulteração:**
   ```sql
   -- No psql como postgres (superusuário):
   UPDATE audit_log SET old_data = '{"adulterado": true}' WHERE id = 1;
   ```
5. `GET /audit/verify` → entradas após id=1 mostram `is_valid: false` ❌

### Teste 4 — Mascaramento Dinâmico
1. `GET /records/masked` → dados mascarados retornados da view SQL
2. No psql como `api_user`:
   ```bash
   docker exec -it secure_db psql -U api_user -d securedb
   ```
   ```sql
   SELECT * FROM financial_records_masked;
   -- Veja: nome mascarado, CPF "[CIFRADO]", DEK "[PROTEGIDO]"
   
   -- Tente acessar tabela raw (deve falhar sem RLS):
   SELECT * FROM financial_records;
   -- Retorna vazio (RLS filtra tudo sem SET LOCAL)
   ```

---

## 📁 Estrutura do Projeto

```
Back-End-banco-de-dados/
├── docker-compose.yml          # Orquestração dos serviços
├── Dockerfile                  # Imagem da API FastAPI
├── requirements.txt            # Dependências Python
├── init.sql                    # Schema, RLS, triggers, RBAC
├── README.md                   # Este arquivo
└── app/
    ├── __init__.py
    ├── main.py                 # Entrypoint FastAPI
    ├── config.py               # Configurações (env vars)
    ├── auth.py                 # JWT + bcrypt
    ├── crypto.py               # Envelope Encryption AES-256-GCM
    ├── database.py             # Sessão assíncrona + RLS injection
    ├── schemas.py              # Pydantic models
    └── routers/
        ├── __init__.py
        ├── auth_router.py      # /auth/register, /auth/login
        ├── records_router.py   # /records CRUD
        └── audit_router.py     # /audit/logs, /audit/verify
```

---

## 🛑 Parar o Ambiente

```bash
# Para os containers (preserva dados)
docker compose stop

# Remove containers e volumes (reset completo)
docker compose down -v
```

---

## 📚 Referências de Segurança

| Mecanismo | Padrão/Referência |
|-----------|-------------------|
| AES-256-GCM | NIST SP 800-38D |
| Envelope Encryption | AWS KMS Developer Guide |
| Row-Level Security | PostgreSQL Documentation 16 |
| Hash Chaining | Blockchain / append-only log patterns |
| RBAC | NIST SP 800-207 (Zero Trust) |
| Mascaramento | LGPD Art. 13 / PCI-DSS Req. 3.4 |
