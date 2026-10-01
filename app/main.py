# =============================================================================
# app/main.py
# Ponto de entrada da aplicação FastAPI.
#
# Este arquivo:
#   - Cria a instância do FastAPI com documentação enriquecida
#   - Registra os routers de autenticação, registros e auditoria
#   - Configura middleware de CORS
#   - Adiciona endpoint de health check
#
# Os 4 mecanismos de segurança são orquestrados aqui de forma integrada:
#   [MECANISMO 1] crypto.py — Envelope Encryption AES-256-GCM
#   [MECANISMO 2] database.py — RLS via SET LOCAL + auth.py (JWT → user_id)
#   [MECANISMO 3] init.sql (triggers) + audit_router.py
#   [MECANISMO 4] init.sql (view mascarada + RBAC) + records_router.py
# =============================================================================

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers.auth_router import router as auth_router
from app.routers.records_router import router as records_router
from app.routers.audit_router import router as audit_router


# ---------------------------------------------------------------------------
# Lifespan: eventos de startup e shutdown da aplicação
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia o ciclo de vida da aplicação."""
    # Startup: poderia iniciar pools, connections, etc.
    print("🚀 API iniciando — mecanismos de segurança ativos:")
    print("   [1] Envelope Encryption (AES-256-GCM)")
    print("   [2] Row-Level Security (PostgreSQL RLS)")
    print("   [3] Audit Hash Chain (SHA-256 triggers)")
    print("   [4] RBAC + Dynamic Data Masking")
    yield
    # Shutdown
    print("🛑 API encerrando.")


# ---------------------------------------------------------------------------
# Instância principal do FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(
    title="🔐 Secure DB API — Projeto Acadêmico",
    redirect_slashes=False,
    description="""
## Sistema de Demonstração de Segurança em Banco de Dados

Este projeto implementa **4 mecanismos de segurança** em uma arquitetura FastAPI + PostgreSQL:

---

### 🔑 Mecanismo 1: Envelope Encryption (AES-256-GCM)
- Campos sensíveis (CPF, valor) são cifrados **antes do INSERT** com AES-256-GCM
- Cada registro tem sua própria **DEK** (Data Encryption Key) de 256 bits
- A DEK é protegida pela **KEK** (Key Encryption Key) — hierarquia de chaves
- Em produção: KEK viria de AWS KMS / HashiCorp Vault / GCP Cloud KMS

### 🛡️ Mecanismo 2: Row-Level Security (RLS)
- Políticas RLS no PostgreSQL garantem **isolamento de tenant**
- A API injeta `SET LOCAL app.current_user_id = '<uuid>'` em cada transação
- **Sem cláusula WHERE no código** — o banco filtra automaticamente
- Teste: crie registros com usuário A, logue como B → B não vê nada

### 🔗 Mecanismo 3: Audit Trail com Hash Chaining
- Triggers SQL gravam logs de auditoria para **INSERT, UPDATE, DELETE**
- Cada entrada contém hash SHA-256 = `hash(dados_atuais + hash_anterior)`
- Adulteração retroativa quebra todos os hashes subsequentes
- Use `GET /audit/verify` para validar a integridade da cadeia

### 👁️ Mecanismo 4: Mascaramento Dinâmico + RBAC
- A API conecta como `api_user` com **apenas permissões DML** (sem DDL)
- View `financial_records_masked` mascara CPF e valor **no nível do banco**
- CPF exibido com apenas 2 últimos dígitos (conformidade LGPD)

---

### 🚦 Como testar
1. `POST /auth/register` → crie um usuário
2. `POST /auth/login` → obtenha o JWT
3. Clique em **Authorize** e cole o token
4. `POST /records` → crie um registro (observe a cifragem)
5. `GET /records/masked` → veja os dados mascarados (Mecanismo 4)
6. `GET /audit/logs` → veja o hash chain (Mecanismo 3)
7. `GET /audit/verify` → valide a integridade da cadeia
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    contact={
        "name": "Projeto Acadêmico — Segurança em BD",
    },
    license_info={
        "name": "MIT",
    },
)


# ---------------------------------------------------------------------------
# Middleware de CORS
# Em produção: restringir origins para o domínio real da aplicação
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restringir em produção!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Registro dos Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router)
app.include_router(records_router)
app.include_router(audit_router)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    tags=["⚙️ Sistema"],
    summary="Health check da API",
    response_class=JSONResponse,
)
async def health_check():
    """
    Endpoint de verificação de saúde.
    Confirma que a API está rodando e lista os mecanismos de segurança ativos.
    """
    return {
        "status": "healthy",
        "service": "secure-db-api",
        "version": "1.0.0",
        "security_mechanisms": {
            "1_envelope_encryption": "AES-256-GCM (app layer)",
            "2_row_level_security": "PostgreSQL RLS policies",
            "3_audit_hash_chain": "SHA-256 trigger-based chain",
            "4_rbac_masking": "api_role + masked view",
        },
    }


# ---------------------------------------------------------------------------
# Handler global de exceções não tratadas
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Captura exceções não tratadas e retorna uma resposta genérica.
    Evita vazar stack traces e detalhes internos para o cliente (information leakage).
    """
    import logging
    logging.exception(f"Exceção não tratada: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor. Consulte os logs."},
    )
