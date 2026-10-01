# =============================================================================
# app/crypto.py
# [MECANISMO 1 - CRIPTOGRAFIA EM NÍVEL DE APLICAÇÃO: ENVELOPE ENCRYPTION]
#
# Implementa a seguinte hierarquia de chaves:
#
#   KEK (Key Encryption Key)
#    └── Protege a DEK (Data Encryption Key)
#         └── Cifra os dados sensíveis (CPF, valor financeiro)
#
# Fluxo de cifragem (encrypt):
#   1. Gera uma DEK aleatória de 256 bits (nova para cada registro)
#   2. Cifra os dados com AES-256-GCM usando a DEK
#   3. Cifra a DEK com AES-256-GCM usando a KEK
#   4. Armazena: ciphertext_dados + dek_cifrada no banco
#
# Fluxo de decifragem (decrypt):
#   1. Recupera a DEK cifrada do banco
#   2. Decifra a DEK com a KEK
#   3. Decifra os dados com a DEK recuperada
#
# Vantagens do Envelope Encryption:
#   - Rotação de chave: basta re-cifrar as DEKs com a nova KEK (sem tocar os dados)
#   - Comprometimento de uma DEK não afeta outros registros
#   - KEK pode ser armazenada em HSM/KMS sem tráfego de dados
# =============================================================================

import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import settings


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
# AES-GCM usa nonce de 12 bytes (96 bits) - padrão NIST recomendado
NONCE_SIZE = 12

# Tamanho da DEK: 32 bytes = 256 bits
DEK_SIZE = 32


def _get_kek() -> bytes:
    """
    Retorna a KEK como bytes a partir do valor hexadecimal configurado.

    [MECANISMO 1 - ENVELOPE ENCRYPTION]
    Em produção, este método chamaria uma API de KMS para obter a KEK
    (ex: AWS KMS.decrypt(), GCP Cloud KMS.decrypt(), HashiCorp Vault).
    Aqui, carregamos da variável de ambiente por simplicidade acadêmica.
    """
    return bytes.fromhex(settings.KEK_HEX)


def _aesgcm_encrypt(key: bytes, plaintext: str) -> str:
    """
    Cifra um texto usando AES-256-GCM.

    AES-GCM é um modo AEAD (Authenticated Encryption with Associated Data):
      - Confidencialidade: garante que apenas quem tem a chave lê o conteúdo.
      - Integridade/Autenticidade: a tag de autenticação detecta qualquer
        adulteração no ciphertext (mesmo 1 bit alterado → falha na decifragem).

    Formato do output (base64):
      nonce (12 bytes) || ciphertext+tag (variável)

    Returns:
        String base64 com nonce prefixado ao ciphertext.
    """
    # Gera um nonce aleatório e único para cada cifragem.
    # NUNCA reutilize nonce com a mesma chave em AES-GCM (quebraria a segurança).
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    # encrypt() retorna ciphertext + tag de autenticação (16 bytes ao final)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Empacota nonce + ciphertext e codifica em base64 para armazenamento em TEXT
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def _aesgcm_decrypt(key: bytes, ciphertext_b64: str) -> str:
    """
    Decifra um texto previamente cifrado com AES-256-GCM.

    Raises:
        cryptography.exceptions.InvalidTag: se o ciphertext foi adulterado.
    """
    raw = base64.b64decode(ciphertext_b64.encode("utf-8"))

    # Separa nonce (primeiros 12 bytes) do ciphertext+tag
    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    # decrypt() valida a tag de autenticação ANTES de retornar o plaintext.
    # Se a tag falhar (adulteração detectada), lança InvalidTag.
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# API PÚBLICA do módulo de criptografia
# ---------------------------------------------------------------------------

def encrypt_field(plaintext: str) -> tuple[str, str]:
    """
    [MECANISMO 1 - ENVELOPE ENCRYPTION]
    Cifra um campo sensível usando uma DEK nova, e cifra a DEK com a KEK.

    Args:
        plaintext: O dado sensível em texto claro (ex: CPF "123.456.789-00")

    Returns:
        Tuple (ciphertext_b64, dek_enc_b64):
          - ciphertext_b64: dado cifrado com a DEK (base64)
          - dek_enc_b64:    DEK cifrada com a KEK (base64) — para armazenar no BD
    """
    kek = _get_kek()

    # Passo 1: Gera uma DEK aleatória exclusiva para este campo/registro
    dek = os.urandom(DEK_SIZE)  # 256 bits de entropia criptográfica

    # Passo 2: Cifra o dado sensível com a DEK
    ciphertext_b64 = _aesgcm_encrypt(dek, plaintext)

    # Passo 3: Cifra a DEK com a KEK (Envelope Encryption)
    dek_enc_b64 = _aesgcm_encrypt(kek, dek.hex())

    return ciphertext_b64, dek_enc_b64


def decrypt_field(ciphertext_b64: str, dek_enc_b64: str) -> str:
    """
    [MECANISMO 1 - ENVELOPE ENCRYPTION]
    Decifra um campo sensível: primeiro decifra a DEK com a KEK,
    depois usa a DEK para decifrar o dado.

    Args:
        ciphertext_b64: Dado cifrado (base64) recuperado do banco
        dek_enc_b64:    DEK cifrada (base64) recuperada do banco

    Returns:
        Texto claro do dado sensível.
    """
    kek = _get_kek()

    # Passo 1: Decifra a DEK usando a KEK
    dek_hex = _aesgcm_decrypt(kek, dek_enc_b64)
    dek = bytes.fromhex(dek_hex)

    # Passo 2: Decifra o dado usando a DEK recuperada
    return _aesgcm_decrypt(dek, ciphertext_b64)


def mask_cpf(cpf: str) -> str:
    """
    [MECANISMO 4 - MASCARAMENTO DINÂMICO]
    Mascara um CPF no formato '123.456.789-00' → '***.456.***-00'.
    Exibe apenas os 4 últimos dígitos, conforme regulamentação LGPD/PCI-DSS.
    """
    # Remove formatação, mantém apenas dígitos
    digits = "".join(c for c in cpf if c.isdigit())
    if len(digits) == 11:
        # Formato: ***.***.***.XX (4 últimos visíveis)
        return f"***.***.***-{digits[-2:]}"
    # Fallback para formatos não-padrão
    return "*" * (len(cpf) - 4) + cpf[-4:] if len(cpf) > 4 else "****"
