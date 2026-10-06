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

import subprocess
import sys
import json

TIMEOUT_SEGUNDOS = 60

def executar_sca(caminho_arquivo: str = "alvo_requirements.txt") -> dict:
    """
    Executa o pip-audit no arquivo de dependências e retorna os dados brutos estruturados.
    """
    try:
        comando = [sys.executable, "-m", "pip_audit", "-r", caminho_arquivo, "-f", "json", "--vulnerability-service", "osv"]
        try:
            processo = subprocess.run(comando, capture_output=True, text=True, timeout=TIMEOUT_SEGUNDOS)
        except subprocess.TimeoutExpired:
            return {"status": "erro", "mensagem": f"O motor SCA excedeu {TIMEOUT_SEGUNDOS}s (possível falha de rede na consulta de vulnerabilidades). Tente novamente."}
        
        if not processo.stdout.strip():
            if processo.stderr.strip():
                return {"status": "erro", "mensagem": f"Falha no motor SCA: {processo.stderr.strip()}"}
            return {"status": "sucesso", "mensagem": "Nenhuma vulnerabilidade nas dependências encontrada!"}
        
        try:
            dados_audit = json.loads(processo.stdout)
        except json.JSONDecodeError:
            return {"status": "erro", "mensagem": "O motor SCA não retornou um JSON válido."}

        dependencias_vulneraveis = dados_audit.get("dependencies", [])
        falhas = [dep for dep in dependencias_vulneraveis if dep.get("vulns")]
        
        if not falhas:
            return {"status": "sucesso", "mensagem": "✅ Nenhuma dependência vulnerável encontrada!"}
            
        # Extrai os dados essenciais se houver falha
        total_falhas = sum(len(dep["vulns"]) for dep in falhas)
        pacote_alvo = falhas[0]
        
        return {
            "status": "vulneravel",
            "total_falhas": total_falhas,
            "nome_pacote": pacote_alvo["name"],
            "versao_pacote": pacote_alvo["version"],
            "cve_id": pacote_alvo["vulns"][0].get("id", "Vulnerabilidade Desconhecida")
        }
        
    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro no motor SCA: {str(erro)}"}