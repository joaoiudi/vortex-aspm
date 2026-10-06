# Vortex ASPM - Application Security Posture Management
# Copyright (C) 2026  João Iudi Oliveira de Souza, Gabriel de Oliveira Gomes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

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