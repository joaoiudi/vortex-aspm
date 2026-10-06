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

import re

def executar_secrets(codigo_fonte: str) -> dict:
    """
    Varre o código-fonte em busca de credenciais e chaves de API expostas em texto claro.
    """
    # Padrões comuns de vazamento mapeados via Expressões Regulares
    padroes = {
        "Chave Genérica (API Key/Token)": r"(?i)(?:api_key|apikey|secret|token|password)[\s:=]+['\"]([a-zA-Z0-9_\-]{16,})['\"]",
        "AWS Access Key": r"(?i)(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
        "Google Cloud / Gemini Key": r"(?i)AIza[0-9A-Za-z\-_]{35}"
    }

    vazamentos_encontrados = []

    # Lê o código linha por linha para identificar o local exato do vazamento
    linhas = codigo_fonte.split('\n')
    for num_linha, linha in enumerate(linhas, start=1):
        for nome_padrao, regex in padroes.items():
            match = re.search(regex, linha)
            if match:
                vazamentos_encontrados.append({
                    "tipo": nome_padrao,
                    "linha": num_linha,
                    "trecho_suspeito": linha.strip()
                })

    if not vazamentos_encontrados:
        return {"status": "sucesso", "mensagem": "✅ Nenhum segredo vazado encontrado!"}

    # Retorna o total de vazamentos e os detalhes da primeira falha
    falha_principal = vazamentos_encontrados[0]
    
    return {
        "status": "vulneravel",
        "total_falhas": len(vazamentos_encontrados),
        "falha_principal": falha_principal
    }