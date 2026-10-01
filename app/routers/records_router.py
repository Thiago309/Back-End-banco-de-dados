# =============================================================================
# app/routers/records_router.py
# Endpoints CRUD para registros financeiros.
#
# Demonstra todos os 4 mecanismos de segurança em conjunto:
#   [MECANISMO 1] Envelope Encryption no POST (cifragem) e GET (decifragem)
#   [MECANISMO 2] RLS via injeção de user_id via SET LOCAL em cada sessão
#   [MECANISMO 3] Hash Chaining ativado automaticamente pelos triggers SQL
#   [MECANISMO 4] View mascarada no GET /masked e RBAC via api_role
# =============================================================================

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from app.auth import get_current_user
from app.crypto import decrypt_field, encrypt_field, mask_cpf
from app.database import get_db_session
from app.schemas import (
    FinancialRecordCreate,
    FinancialRecordMasked,
    FinancialRecordResponse,
)

router = APIRouter(prefix="/records", tags=["💳 Registros Financeiros"])


# ---------------------------------------------------------------------------
# POST /records — Criar registro com dados cifrados
# ---------------------------------------------------------------------------
@router.post(
    "",
    response_model=FinancialRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar registro financeiro (com cifragem AES-256-GCM)",
    description=(
        "**[Mecanismo 1 - Envelope Encryption]** CPF e valor são cifrados com "
        "AES-256-GCM usando uma DEK única por registro, protegida pela KEK.\n\n"
        "**[Mecanismo 2 - RLS]** O owner_id é definido pelo JWT autenticado.\n\n"
        "**[Mecanismo 3 - Hash Chain]** O trigger SQL gera automaticamente um "
        "registro de auditoria com hash encadeado após o INSERT.\n\n"
        "**[Mecanismo 4 - RBAC]** A operação usa a role api_role (somente DML)."
    ),
)
async def create_record(
    payload: FinancialRecordCreate,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    # [MECANISMO 1 - ENVELOPE ENCRYPTION]
    # Cifra CPF com DEK própria, cifra a DEK com a KEK global
    cpf_enc, dek_enc_cpf = encrypt_field(payload.cpf)
    valor_enc, dek_enc_valor = encrypt_field(str(payload.valor))
    combined_dek_enc = f"{dek_enc_cpf}||{dek_enc_valor}"

    # [MECANISMO 2 - RLS]
    # async with garante commit ao sair do bloco — SET LOCAL ativo durante todo o INSERT
    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                INSERT INTO financial_records
                    (owner_id, nome, cpf_enc, valor_enc, dek_enc)
                VALUES
                    (:owner_id, :nome, :cpf_enc, :valor_enc, :dek_enc)
                RETURNING
                    id, owner_id, nome, cpf_enc, valor_enc, dek_enc,
                    created_at, updated_at
                """
            ),
            {
                "owner_id": user_id,
                "nome": payload.nome,
                "cpf_enc": cpf_enc,
                "valor_enc": valor_enc,
                "dek_enc": combined_dek_enc,
            },
        )
        row = result.fetchone()

        # [MECANISMO 1] Decifra para retornar ao cliente
        dek_enc_cpf_s, dek_enc_valor_s = row.dek_enc.split("||", 1)
        cpf_decifrado = decrypt_field(row.cpf_enc, dek_enc_cpf_s)
        valor_decifrado = float(decrypt_field(row.valor_enc, dek_enc_valor_s))

        # [MECANISMO 4] Mascara CPF antes de retornar
        return FinancialRecordResponse(
            id=row.id,
            owner_id=row.owner_id,
            nome=row.nome,
            cpf_mascarado=mask_cpf(cpf_decifrado),
            valor=valor_decifrado,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
    # [MECANISMO 3] O trigger trg_financial_audit disparou automaticamente no INSERT


# ---------------------------------------------------------------------------
# GET /records/masked — ANTES de /{record_id} para evitar conflito de rota
# [MECANISMO 4 - MASCARAMENTO DINÂMICO]
# ---------------------------------------------------------------------------
@router.get(
    "/masked",
    response_model=List[FinancialRecordMasked],
    summary="Listar registros via view mascarada do banco (Mecanismo 4)",
    description=(
        "**[Mecanismo 4 - Mascaramento Dinâmico]** Consulta a view "
        "`financial_records_masked` criada no PostgreSQL. O mascaramento ocorre "
        "no nível do banco — mesmo acessando o BD diretamente com api_user, "
        "os dados aparecem mascarados.\n\n"
        "**[Mecanismo 2 - RLS]** A view herda as políticas RLS da tabela base."
    ),
)
async def list_masked_records(
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                SELECT id, owner_id, nome_mascarado, cpf_mascarado,
                       valor_mascarado, dek_status, created_at, updated_at
                FROM financial_records_masked
                ORDER BY created_at DESC
                """
            )
        )
        rows = result.fetchall()
        return [
            FinancialRecordMasked(
                id=row.id,
                owner_id=row.owner_id,
                nome_mascarado=row.nome_mascarado,
                cpf_mascarado=row.cpf_mascarado,
                valor_mascarado=row.valor_mascarado,
                dek_status=row.dek_status,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ]


# ---------------------------------------------------------------------------
# GET /records — Listar registros decifrados do owner autenticado
# ---------------------------------------------------------------------------
@router.get(
    "",
    response_model=List[FinancialRecordResponse],
    summary="Listar meus registros (decifrados, com CPF mascarado)",
    description=(
        "**[Mecanismo 2 - RLS]** Retorna APENAS os registros do usuário autenticado. "
        "O PostgreSQL filtra automaticamente via política RLS — não há cláusula WHERE "
        "no código Python. Tente acessar com outro usuário para confirmar o isolamento.\n\n"
        "**[Mecanismo 1]** CPF e valor são decifrados pela API antes do retorno.\n\n"
        "**[Mecanismo 4]** CPF é exibido mascarado (apenas 2 últimos dígitos)."
    ),
)
async def list_my_records(
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    # [MECANISMO 2 - RLS] Sem WHERE owner_id — o banco filtra automaticamente
    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                SELECT id, owner_id, nome, cpf_enc, valor_enc, dek_enc,
                       created_at, updated_at
                FROM financial_records
                ORDER BY created_at DESC
                """
            )
        )
        rows = result.fetchall()
        records = []
        for row in rows:
            dek_enc_cpf_s, dek_enc_valor_s = row.dek_enc.split("||", 1)
            cpf_decifrado = decrypt_field(row.cpf_enc, dek_enc_cpf_s)
            valor_decifrado = float(decrypt_field(row.valor_enc, dek_enc_valor_s))
            records.append(
                FinancialRecordResponse(
                    id=row.id,
                    owner_id=row.owner_id,
                    nome=row.nome,
                    cpf_mascarado=mask_cpf(cpf_decifrado),
                    valor=valor_decifrado,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
            )
        return records


# ---------------------------------------------------------------------------
# GET /records/{record_id} — Buscar registro específico (decifrado)
# ---------------------------------------------------------------------------
@router.get(
    "/{record_id}",
    response_model=FinancialRecordResponse,
    summary="Buscar registro por ID (com RLS e decifragem)",
    description=(
        "**[Mecanismo 2 - RLS]** Se tentar acessar um registro de outro usuário, "
        "o banco retorna 0 linhas (como se o registro não existisse). "
        "A política RLS bloqueia silenciosamente."
    ),
)
async def get_record(
    record_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                SELECT id, owner_id, nome, cpf_enc, valor_enc, dek_enc,
                       created_at, updated_at
                FROM financial_records
                WHERE id = :rid
                """
                # [MECANISMO 2 - RLS] Sem WHERE owner_id — RLS filtra automaticamente
            ),
            {"rid": str(record_id)},
        )
        row = result.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registro não encontrado ou acesso não autorizado.",
            )

        dek_enc_cpf_s, dek_enc_valor_s = row.dek_enc.split("||", 1)
        cpf_decifrado = decrypt_field(row.cpf_enc, dek_enc_cpf_s)
        valor_decifrado = float(decrypt_field(row.valor_enc, dek_enc_valor_s))

        return FinancialRecordResponse(
            id=row.id,
            owner_id=row.owner_id,
            nome=row.nome,
            cpf_mascarado=mask_cpf(cpf_decifrado),
            valor=valor_decifrado,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


# ---------------------------------------------------------------------------
# PUT /records/{record_id} — Atualizar registro
# ---------------------------------------------------------------------------
@router.put(
    "/{record_id}",
    response_model=FinancialRecordResponse,
    summary="Atualizar registro (re-cifra os dados e gera novo log de auditoria)",
    description=(
        "**[Mecanismo 1]** Os novos dados são cifrados com DEKs novas.\n\n"
        "**[Mecanismo 2 - RLS]** O WITH CHECK da política garante que não é possível "
        "atualizar registros de outros usuários.\n\n"
        "**[Mecanismo 3]** O trigger gera automaticamente um log UPDATE "
        "com hash encadeado ao anterior."
    ),
)
async def update_record(
    record_id: UUID,
    payload: FinancialRecordCreate,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    cpf_enc, dek_enc_cpf = encrypt_field(payload.cpf)
    valor_enc, dek_enc_valor = encrypt_field(str(payload.valor))
    combined_dek_enc = f"{dek_enc_cpf}||{dek_enc_valor}"

    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                UPDATE financial_records
                SET nome = :nome,
                    cpf_enc = :cpf_enc,
                    valor_enc = :valor_enc,
                    dek_enc = :dek_enc,
                    updated_at = NOW()
                WHERE id = :rid
                RETURNING id, owner_id, nome, cpf_enc, valor_enc, dek_enc,
                          created_at, updated_at
                """
            ),
            {
                "rid": str(record_id),
                "nome": payload.nome,
                "cpf_enc": cpf_enc,
                "valor_enc": valor_enc,
                "dek_enc": combined_dek_enc,
            },
        )
        row = result.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registro não encontrado ou acesso não autorizado.",
            )

        dek_enc_cpf_s, dek_enc_valor_s = row.dek_enc.split("||", 1)
        cpf_decifrado = decrypt_field(row.cpf_enc, dek_enc_cpf_s)
        valor_decifrado = float(decrypt_field(row.valor_enc, dek_enc_valor_s))

        return FinancialRecordResponse(
            id=row.id,
            owner_id=row.owner_id,
            nome=row.nome,
            cpf_mascarado=mask_cpf(cpf_decifrado),
            valor=valor_decifrado,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


# ---------------------------------------------------------------------------
# DELETE /records/{record_id} — Deletar registro
# ---------------------------------------------------------------------------
@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deletar registro (gera log de auditoria DELETE com hash chain)",
    description=(
        "**[Mecanismo 2 - RLS]** Só é possível deletar registros próprios.\n\n"
        "**[Mecanismo 3]** O trigger gera um log DELETE encadeado — "
        "os dados deletados ficam preservados na auditoria de forma imutável."
    ),
)
async def delete_record(
    record_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]

    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text("DELETE FROM financial_records WHERE id = :rid RETURNING id"),
            {"rid": str(record_id)},
        )
        row = result.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registro não encontrado ou acesso não autorizado.",
            )
        return None
