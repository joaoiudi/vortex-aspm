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

import json
from ia.gemini import analisar_codigo_autonomo

def executar_sast(caminho_arquivo: str) -> dict:
    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            codigo_fonte = f.read()
            
        if not codigo_fonte.strip():
            return {"status": "sucesso", "mensagem": "✅ O arquivo está vazio."}

        resposta_ia = analisar_codigo_autonomo(codigo_fonte)
        
        resposta_str = str(resposta_ia)
        if "```json" in resposta_str:
            resposta_str = resposta_str.split("```json")[1].split("```")[0]
        elif "```" in resposta_str:
            resposta_str = resposta_str.split("```")[1].split("```")[0]
            
        dados_analise = json.loads(resposta_str.strip())
        
        if dados_analise.get("status") == "erro" or "erro" in dados_analise:
            return {"status": "erro", "mensagem": dados_analise.get("mensagem", "Erro na análise via IA.")}
        
        if dados_analise.get("total_falhas", 0) == 0:
            return {"status": "sucesso", "mensagem": "✅ Nenhuma vulnerabilidade encontrada pela análise autônoma!"}
            
        return {
            "status": "vulneravel",
            "total_falhas": dados_analise["total_falhas"],
            "severidade": dados_analise.get("severidade_maxima", "ALTO"),
            "detalhes_lista": dados_analise["detalhes_lista"]
        }
        
    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno durante a execução do motor SAST: {str(erro)}"}