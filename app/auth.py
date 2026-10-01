# =============================================================================
# app/auth.py
# Autenticação JWT — simula o sistema de identidade que alimenta o RLS.
#
# [MECANISMO 2 - RLS]
# O user_id extraído do token JWT é o mesmo injetado no banco via SET LOCAL.
# Isso garante que o contexto de segurança da API == contexto do banco.
# =============================================================================

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings

# ---------------------------------------------------------------------------
# Configuração de hashing de senha (bcrypt)
# ---------------------------------------------------------------------------
# bcrypt é o algoritmo recomendado para hashing de senhas:
# - Adaptativo (custo configurável)
# - Salt automático embutido no hash
# - Resistente a ataques de força bruta por GPU
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Bearer Token: o Swagger UI usará este esquema para autenticação
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ---------------------------------------------------------------------------
# Schemas Pydantic para autenticação
# ---------------------------------------------------------------------------
class TokenPayload(BaseModel):
    """Payload do JWT token."""
    sub: str        # subject = user_id (UUID)
    username: str
    exp: datetime


class TokenResponse(BaseModel):
    """Resposta do endpoint de login."""
    access_token: str
    token_type: str = "bearer"
    user_id: str


# ---------------------------------------------------------------------------
# Funções de utilitário
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Gera hash bcrypt de uma senha em texto claro."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha em texto claro corresponde ao hash bcrypt."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, username: str) -> str:
    """
    Cria um JWT assinado com HS256 contendo o user_id como 'sub'.

    [MECANISMO 2 - RLS]
    O user_id aqui é o mesmo que será injetado no banco via SET LOCAL.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "username": username,
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    FastAPI Dependency: decodifica o JWT e retorna os dados do usuário.

    [MECANISMO 2 - RLS]
    O user_id retornado aqui é passado para get_db_session() que o injeta
    no banco via SET LOCAL app.current_user_id.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return {"user_id": user_id, "username": username}
