# =============================================================================
# app/routers/auth_router.py
# Endpoints de autenticação: /register e /login
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text

from app.auth import create_access_token, hash_password, verify_password
from app.database import get_db_session
from app.schemas import TokenResponse, UserRegisterRequest

router = APIRouter(prefix="/auth", tags=["🔐 Autenticação"])


@router.post(
    "/register",
    response_model=TokenResponse,
    summary="Registrar novo usuário",
    description="Cria um novo usuário com senha hashada (bcrypt) e retorna um JWT.",
)
async def register(payload: UserRegisterRequest):
    """Registra um novo usuário com senha bcrypt."""
    async with get_db_session(user_id=None) as session:
        result = await session.execute(
            text("SELECT id FROM app_users WHERE username = :u"),
            {"u": payload.username},
        )
        if result.fetchone():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Usuário '{payload.username}' já existe.",
            )

        hashed = hash_password(payload.password)
        result = await session.execute(
            text(
                "INSERT INTO app_users (username, hashed_password) "
                "VALUES (:u, :h) RETURNING id"
            ),
            {"u": payload.username, "h": hashed},
        )
        row = result.fetchone()
        user_id = str(row[0])
        token = create_access_token(user_id=user_id, username=payload.username)
        return TokenResponse(access_token=token, user_id=user_id)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login de usuário",
    description=(
        "Autentica com username/password e retorna um JWT Bearer token. "
        "Use o token no botão 'Authorize' do Swagger para testar os demais endpoints."
    ),
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login via OAuth2 Password Flow.

    [MECANISMO 2 - RLS]
    O JWT retornado contém o user_id como claim 'sub'.
    Esse user_id é injetado no banco via SET LOCAL em cada requisição.
    """
    async with get_db_session(user_id=None) as session:
        result = await session.execute(
            text("SELECT id, hashed_password FROM app_users WHERE username = :u"),
            {"u": form_data.username},
        )
        row = result.fetchone()

        if not row or not verify_password(form_data.password, row[1]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = str(row[0])
        token = create_access_token(user_id=user_id, username=form_data.username)
        return TokenResponse(access_token=token, user_id=user_id)
