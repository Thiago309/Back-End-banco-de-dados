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

## 🧪 Testes Automatizados e Provas de Segurança

Para facilitar a validação e demonstração dos 4 mecanismos implementados, o projeto conta com uma suíte de testes E2E (API) e provas diretas no banco de dados, bypassando a aplicação.

Veja as instruções completas de como executar os scripts de teste no arquivo dedicado:
👉 **[INSTRUCOES_TESTE.md](./INSTRUCOES_TESTE.md)**

### Scripts Disponíveis
1. **`test_security.py`**: Utiliza `pytest` para simular requisições reais à API e comprovar o bloqueio de acessos indevidos via **Row-Level Security (RLS)** e o Mascaramento de dados restritos.
2. **`prove_security.py`**: Conecta-se diretamente ao PostgreSQL via `psycopg2` (como Super Administrador), burlando a API. Serve para provar matematicamente a integridade da **Hash Chain** (Auditoria) e a absoluta ilegibilidade dos dados criptografados no armazenamento físico (**Envelope Encryption**).
3. **Teste Interativo (Manual):** Acesse a interface Swagger em `http://localhost:8000/docs` para interagir visualmente com os endpoints e simular os acessos.

---

## 📁 Estrutura do Projeto

```text
Back-End-banco-de-dados/
├── docker-compose.yml          # Orquestração dos serviços
├── Dockerfile                  # Imagem da API FastAPI
├── requirements.txt            # Dependências Python
├── init.sql                    # Schema, RLS, triggers, RBAC
├── test_security.py            # Suíte de Testes Automatizados da API
├── prove_security.py           # Script de Prova Bypass direto no BD
├── INSTRUCOES_TESTE.md         # Roteiro de Testes para Avaliação
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
