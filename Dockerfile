FROM python:3.10-slim

WORKDIR /app

# Instala ferramentas essenciais do sistema
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Copia e instala as dependências explicitamente garantindo o caminho global
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copia o restante do código
COPY . .

EXPOSE 8000
EXPOSE 8501