# =============================================================================
# app/routers/audit_router.py
# Endpoints para consulta da trilha de auditoria com hash chaining.
#
# [MECANISMO 3 - TRILHA DE AUDITORIA COM HASH CHAINING]
# =============================================================================

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.auth import get_current_user
from app.database import get_db_session
from app.schemas import AuditChainVerification, AuditLogEntry

router = APIRouter(prefix="/audit", tags=["🔍 Auditoria (Hash Chain)"])


@router.get(
    "/logs",
    response_model=List[AuditLogEntry],
    summary="Listar todos os logs de auditoria",
    description=(
        "**[Mecanismo 3 - Hash Chaining]** Cada entrada contém:\n"
        "- `row_hash`: SHA-256 encadeado com hash anterior\n"
        "- `prev_hash`: hash da entrada anterior\n"
        "- `old_data`/`new_data`: snapshots antes/depois da operação\n\n"
        "Use `/audit/verify` para confirmar a integridade da cadeia."
    ),
)
async def list_audit_logs(
    current_user: dict = Depends(get_current_user),
    limit: int = 100,
    offset: int = 0,
):
    user_id = current_user["user_id"]
    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                SELECT id, record_id, operation, performed_by,
                       old_data, new_data, event_at, row_hash, prev_hash
                FROM audit_log
                ORDER BY id DESC
                LIMIT :lim OFFSET :off
                """
            ),
            {"lim": limit, "off": offset},
        )
        rows = result.fetchall()
        return [
            AuditLogEntry(
                id=row.id,
                record_id=row.record_id,
                operation=row.operation,
                performed_by=row.performed_by,
                old_data=row.old_data,
                new_data=row.new_data,
                event_at=row.event_at,
                row_hash=row.row_hash,
                prev_hash=row.prev_hash,
            )
            for row in rows
        ]


@router.get(
    "/verify",
    response_model=List[AuditChainVerification],
    summary="Verificar integridade da cadeia de hashes",
    description=(
        "**[Mecanismo 3 - Hash Chaining]** Executa `verify_audit_chain()` "
        "no PostgreSQL, que recalcula todos os hashes e compara com os armazenados.\n\n"
        "- `is_valid: true` → ✅ cadeia íntegra\n"
        "- `is_valid: false` → ❌ **ADULTERAÇÃO DETECTADA**\n\n"
        "Qualquer linha adulterada invalida todas as entradas subsequentes."
    ),
)
async def verify_audit_chain(
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]
    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                "SELECT log_id, is_valid, stored_hash, computed_hash "
                "FROM verify_audit_chain()"
            )
        )
        rows = result.fetchall()
        return [
            AuditChainVerification(
                log_id=row.log_id,
                is_valid=row.is_valid,
                stored_hash=row.stored_hash,
                computed_hash=row.computed_hash,
            )
            for row in rows
        ]


@router.get(
    "/logs/{record_id}",
    response_model=List[AuditLogEntry],
    summary="Histórico de auditoria de um registro específico",
    description=(
        "**[Mecanismo 3]** Todas as entradas de auditoria "
        "(INSERT, UPDATE, DELETE) de um record_id, em ordem cronológica."
    ),
)
async def get_record_audit_history(
    record_id: str,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]
    async with get_db_session(user_id=user_id) as session:
        result = await session.execute(
            text(
                """
                SELECT id, record_id, operation, performed_by,
                       old_data, new_data, event_at, row_hash, prev_hash
                FROM audit_log
                WHERE record_id = :rid
                ORDER BY id ASC
                """
            ),
            {"rid": record_id},
        )
        rows = result.fetchall()
        return [
            AuditLogEntry(
                id=row.id,
                record_id=row.record_id,
                operation=row.operation,
                performed_by=row.performed_by,
                old_data=row.old_data,
                new_data=row.new_data,
                event_at=row.event_at,
                row_hash=row.row_hash,
                prev_hash=row.prev_hash,
            )
            for row in rows
        ]
