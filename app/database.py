# =============================================================================
# app/database.py
# Configuração da conexão assíncrona com o PostgreSQL via SQLAlchemy + asyncpg.
#
# [MECANISMO 2 - RLS]
# get_db_session injeta o user_id autenticado via SET LOCAL antes de
# qualquer query, ativando a política de isolamento de tenant no PostgreSQL.
# =============================================================================

from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import settings


# ---------------------------------------------------------------------------
# Engine assíncrona
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    poolclass=NullPool,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# [MECANISMO 2 - ROW-LEVEL SECURITY]
# Context manager assíncrono que abre sessão, configura RLS e garante commit.
#
# Uso nos routers:
#   async with get_db_session(user_id=user_id) as session:
#       result = await session.execute(...)
#
# O "async with session.begin()" faz commit ao sair normalmente
# e rollback se uma exceção for levantada — garantido pelo SQLAlchemy.
# ---------------------------------------------------------------------------
@asynccontextmanager
async def get_db_session(user_id: str | None = None):
    """
    Abre uma sessão com transação e injeta o user_id no contexto do PostgreSQL.

    Args:
        user_id: UUID do usuário autenticado (do JWT). None = sem RLS.
    """
    async with AsyncSessionLocal() as session:
        async with session.begin():
            if user_id:
                # [MECANISMO 2 - RLS]
                # SET LOCAL não aceita bind parameters — interpolamos o UUID
                # após validação para evitar SQL injection.
                import uuid as _uuid
                _uuid.UUID(user_id)  # ValueError se não for UUID válido
                await session.execute(
                    text(f"SET LOCAL app.current_user_id = '{user_id}'")
                )
            # yield dentro de "async with session.begin()" garante:
            # - commit ao sair normalmente
            # - rollback automático em exceção
            yield session
