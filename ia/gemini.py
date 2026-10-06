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

import os
import json
import time
from dotenv import load_dotenv
from google import genai

load_dotenv()
chave_secreta = os.getenv("GEMINI_API_KEY")

if not chave_secreta:
    raise ValueError("A chave GEMINI_API_KEY não foi encontrada no arquivo .env")

cliente = genai.Client(api_key=chave_secreta)

MODELO_GEMINI = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
TENTATIVAS_MAXIMAS = 2
ESPERA_ENTRE_TENTATIVAS_SEGUNDOS = 2


def _chamar_gemini_com_retry(prompt: str) -> str:
    """Chama a API do Gemini com uma tentativa extra em caso de falha
    transitória de rede (não protege contra chave inválida ou quota
    esgotada, que falham de forma consistente em qualquer tentativa)."""
    ultimo_erro = None
    for tentativa in range(1, TENTATIVAS_MAXIMAS + 1):
        try:
            resposta = cliente.models.generate_content(model=MODELO_GEMINI, contents=prompt)
            return resposta.text
        except Exception as erro:
            ultimo_erro = erro
            if tentativa < TENTATIVAS_MAXIMAS:
                time.sleep(ESPERA_ENTRE_TENTATIVAS_SEGUNDOS)
    if ultimo_erro is not None:
        raise ultimo_erro
    raise RuntimeError("Falha desconhecida ao chamar a API do Gemini.")

def gerar_remediacao_ia(tipo_motor: str, detalhes: str, score_risco: int = None) -> str:
    """
    Gera a remediação estruturada em formato de Ticket corporativo,
    separando o modelo de acordo com o motor de segurança acionado.
    """
    
    if tipo_motor == "sca":
        prompt = f"""
        Você é o motor de IA de uma plataforma ASPM corporativa. 
        Detectamos uma dependência vulnerável: '{detalhes}'.
        
        Gere a resposta obrigatoriamente seguindo este formato fixo de Ticket de Incidente:

        [ALERTA ASPM - SCA] Vulnerabilidade Crítica Detectada
        - CVE: [Informe o identificador da CVE ou ID do advisory]
        - Pacote: [Nome e versão da biblioteca vulnerável]
        - Risco: [Descreva o impacto de segurança]
        - Ação Requerida: [Passo a passo exato para atualizar no requirements.txt]
        """
        
    elif tipo_motor == "secrets":
        prompt = f"""
        Você é o motor de IA de uma plataforma ASPM corporativa. 
        Detectamos uma credencial/segredo vazado no código-fonte: '{detalhes}'.
        
        Gere a resposta obrigatoriamente seguindo este formato fixo de Ticket de Incidente:

        [ALERTA ASPM - SECRETS] Vazamento de Credencial Exposta
        - Tipo de Segredo: [Ex: Chave de API, Token JWT ou Senha Hardcoded]
        - Impacto: [Riscos de acesso indevido à infraestrutura]
        - Ação Requerida: [Instruir a revogação imediata da chave e uso de os.getenv]
        """
        
    elif tipo_motor == "dast":
        linha_score = f"\n        Score de Risco calculado para esta varredura: {score_risco}/100." if score_risco is not None else ""
        prompt = f"""
        Você é o motor de IA de uma plataforma ASPM corporativa. 
        Uma varredura dinâmica (DAST) contra a aplicação em execução encontrou: '{detalhes}'.{linha_score}
        
        Gere a resposta obrigatoriamente seguindo este formato fixo de Ticket de Incidente:

        [ALERTA ASPM - DAST] Vulnerabilidade Detectada em Tempo de Execução
        - Vulnerabilidade: [Nome do problema encontrado durante o teste dinâmico]
        - Risco: [O que um invasor pode explorar acessando a aplicação em produção]
        - Ação Requerida: [Configuração ou mudança de código necessária para corrigir]
        """

    else:  # SAST
        prompt = f"""
        Você é o motor de IA de uma plataforma ASPM corporativa. 
        Detectamos uma falha estrutural no código-fonte: '{detalhes}'.
        
        Gere a resposta obrigatoriamente seguindo este formato fixo de Ticket de Incidente:

        [ALERTA ASPM - SAST] Falha de Segurança Estrutural no Código
        - Vulnerabilidade: [Nome da falha de programação]
        - Risco: [O que um invasor pode explorar]
        - Ação Requerida: [Apresentar o trecho de código seguro corrigido para substituir a falha]
        """

    try:
        return _chamar_gemini_com_retry(prompt)
    except Exception as erro:
        return f"Erro de comunicação com a IA: {str(erro)}"

def analisar_codigo_autonomo(codigo_fonte: str) -> str:
    """
    Função dedicada exclusivamente à análise estática autônoma via IA,
    retornando estritamente um JSON estruturado com as falhas encontradas.
    """
    prompt = f"""
    Aja como um motor SAST (Static Application Security Testing) automatizado de ponta.
    Analise o código fonte Python abaixo e identifique TODAS as vulnerabilidades de segurança, falhas lógicas, 
    problemas de arquitetura ou exposição de dados presentes.

    IMPORTANTE - FORA DO SEU ESCOPO: NÃO reporte credenciais hardcoded, chaves de
    API, tokens, senhas ou segredos expostos em texto claro no código. Essa
    categoria é responsabilidade de um motor dedicado (Secrets Detection) que
    roda separadamente, e reportá-la aqui também causaria contagem duplicada da
    mesma falha. Ignore esses casos completamente, mesmo que os veja no código,
    e foque apenas em falhas estruturais/lógicas: SQL Injection, Command
    Injection, uso inseguro de eval()/exec(), Path Traversal, deserialização
    insegura (pickle), criptografia fraca (ex: MD5 sem salt), Remote Code
    Execution, e problemas de arquitetura/lógica de forma geral.

    Código fonte:
    {codigo_fonte}

    Retorne a resposta EXATAMENTE no formato JSON válido abaixo, sem blocos de markdown adicionais, sem texto antes ou depois, contendo rigorosamente esta estrutura:
    {{
        "total_falhas": <número total de falhas encontradas>,
        "severidade_maxima": "<CRÍTICO/ALTO/MÉDIO/BAIXO>",
        "detalhes_lista": [
            {{
                "issue_text": "Descrição clara e direta da vulnerabilidade",
                "issue_severity": "<CRÍTICO/ALTO/MÉDIO/BAIXO>",
                "line_number": <número aproximado da linha ou 0>,
                "test_id": "AI-AUTONOMOUS-01"
            }}
        ]
    }}
    Se o código for totalmente seguro e não tiver falhas, retorne "total_falhas": 0 e a lista vazia.
    """

    try:
        return _chamar_gemini_com_retry(prompt)
    except Exception as erro:
        return json.dumps({"total_falhas": 0, "erro": str(erro)})