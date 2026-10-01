# =============================================================================
# app/config.py
# Configurações da aplicação lidas de variáveis de ambiente.
# =============================================================================

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configurações centralizadas via variáveis de ambiente.
    Pydantic-settings valida os tipos automaticamente.
    """

    # URL de conexão com o banco (usa api_user - Mecanismo 4)
    DATABASE_URL: str

    # [MECANISMO 1 - ENVELOPE ENCRYPTION]
    # KEK em hexadecimal de 32 bytes (256 bits) - Key Encryption Key
    # Em produção: viria de AWS KMS, HashiCorp Vault, GCP Cloud KMS, etc.
    KEK_HEX: str

    # Chave secreta para assinar tokens JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# Instância global de configurações (importada pelos demais módulos)
settings = Settings()
