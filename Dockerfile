# =============================================================================
# Dockerfile
# Imagem da aplicação FastAPI
# =============================================================================

FROM python:3.12-slim

# Metadados
LABEL maintainer="academic-security-project"
LABEL description="FastAPI com 4 mecanismos de segurança para BD"

# Variável de ambiente para evitar buffering dos logs Python
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Diretório de trabalho dentro do container
WORKDIR /app

# Copia e instala dependências primeiro (melhor uso do cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY app/ ./app/

# Expõe a porta da API
EXPOSE 8000

# Comando de inicialização com uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
