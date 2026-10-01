# =============================================================================
# app/schemas.py
# Schemas Pydantic para validação de entrada/saída da API.
# =============================================================================

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Schemas de Autenticação
# ---------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    """Dados para registro de novo usuário."""
    username: str = Field(..., min_length=3, max_length=50, examples=["alice"])
    password: str = Field(..., min_length=8, examples=["senha_segura_123"])


class UserLoginRequest(BaseModel):
    """Dados para login (OAuth2 também aceita form data via /auth/login)."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Resposta de autenticação bem-sucedida."""
    access_token: str
    token_type: str = "bearer"
    user_id: str


# ---------------------------------------------------------------------------
# Schemas de Registros Financeiros
# ---------------------------------------------------------------------------

class FinancialRecordCreate(BaseModel):
    """
    Dados de entrada para criação de um registro financeiro.

    [MECANISMO 1 - ENVELOPE ENCRYPTION]
    CPF e valor são recebidos em texto claro e serão cifrados
    com AES-256-GCM antes de qualquer INSERT no banco.
    """
    nome: str = Field(
        ...,
        min_length=2,
        max_length=200,
        description="Nome completo do titular",
        examples=["João da Silva Sauro"],
    )
    cpf: str = Field(
        ...,
        min_length=11,
        max_length=14,
        description="CPF do titular (com ou sem formatação)",
        examples=["123.456.789-00"],
    )
    valor: float = Field(
        ...,
        gt=0,
        description="Valor financeiro em reais (> 0)",
        examples=[15750.00],
    )


class FinancialRecordResponse(BaseModel):
    """
    Resposta com dados DECIFRADOS (apenas para o owner autenticado).

    [MECANISMO 1] CPF e valor são decifrados pela API após busca no banco.
    [MECANISMO 4] CPF é exibido mascarado mesmo após decifragem.
    [MECANISMO 2] RLS garante que apenas o owner recebe este objeto.
    """
    id: UUID
    owner_id: UUID
    nome: str
    cpf_mascarado: str = Field(description="CPF parcialmente mascarado (LGPD)")
    valor: float = Field(description="Valor financeiro decifrado")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FinancialRecordMasked(BaseModel):
    """
    Resposta da view mascarada do banco (consulta padrão de leitura).

    [MECANISMO 4 - MASCARAMENTO DINÂMICO]
    Dados retornados diretamente da view financial_records_masked do PostgreSQL.
    O mascaramento ocorre no nível do banco — mesmo um DBA com SELECT
    verá apenas os dados mascarados nesta view.
    """
    id: UUID
    owner_id: UUID
    nome_mascarado: str = Field(description="Nome com 3 primeiras letras visíveis")
    cpf_mascarado: str = Field(description="Apenas prefixo do ciphertext visível")
    valor_mascarado: str = Field(description="Apenas prefixo do ciphertext visível")
    dek_status: str = Field(description="Indica que a DEK está protegida")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Schemas de Auditoria
# ---------------------------------------------------------------------------

class AuditLogEntry(BaseModel):
    """
    Entrada da trilha de auditoria.

    [MECANISMO 3 - HASH CHAINING]
    row_hash: hash SHA-256 desta entrada + hash da anterior (cadeia).
    prev_hash: hash armazenado da entrada anterior.
    """
    id: int
    record_id: UUID
    operation: str = Field(description="INSERT, UPDATE ou DELETE")
    performed_by: Optional[str] = Field(description="UUID do usuário que executou a operação")
    old_data: Optional[dict] = Field(description="Snapshot dos dados antes da operação")
    new_data: Optional[dict] = Field(description="Snapshot dos dados após a operação")
    event_at: datetime
    row_hash: str = Field(description="Hash SHA-256 encadeado desta entrada")
    prev_hash: Optional[str] = Field(description="Hash da entrada anterior na cadeia")

    model_config = {"from_attributes": True}


class AuditChainVerification(BaseModel):
    """
    Resultado da verificação de integridade da cadeia de auditoria.

    [MECANISMO 3 - HASH CHAINING]
    """
    log_id: int
    is_valid: bool
    stored_hash: str
    computed_hash: str
