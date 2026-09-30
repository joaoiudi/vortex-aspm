"""
Utilitário: Listar Modelos Disponíveis do Google Gemini

Este script faz a leitura da GEMINI_API_KEY configurada no arquivo .env
e consulta a API do Google GenAI para listar todos os modelos suportados
e disponíveis para a sua chave (ex: gemini-2.5-flash, gemini-1.5-pro, etc.).
"""

import os
import sys
from dotenv import load_dotenv
from google import genai

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Carrega a chave da API a partir do arquivo .env
load_dotenv()
chave_api = os.getenv("GEMINI_API_KEY")

if not chave_api:
    raise ValueError(
        "Chave GEMINI_API_KEY não encontrada! Certifique-se de configurar o arquivo .env a partir do .env.example."
    )

cliente = genai.Client(api_key=chave_api)

print("🔍 Consultando modelos disponíveis para a chave configurada...")
try:
    modelos = list(cliente.models.list())
    print(f"\n✅ Total de {len(modelos)} modelos encontrados:")
    for modelo in modelos:
        print(f" - {modelo.name}")
except Exception as erro:
    print(f"❌ Erro ao listar modelos: {erro}")