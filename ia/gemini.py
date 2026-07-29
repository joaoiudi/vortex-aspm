import os
from dotenv import load_dotenv
from google import genai

# Carrega as variáveis de dentro do arquivo .env para a memória
load_dotenv()

# Pega a chave secreta com segurança
chave_secreta = os.getenv("GEMINI_API_KEY")

if not chave_secreta:
    raise ValueError("A chave GEMINI_API_KEY não foi encontrada no arquivo .env")

# Inicia o cliente
cliente = genai.Client(api_key=chave_secreta)

def gerar_remediacao_ia(tipo_motor: str, detalhes: str) -> str:
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
        
    else:  # SAST (Padrão para código-fonte)
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
        resposta = cliente.models.generate_content(
            model='gemini-3.5-flash-lite', 
            contents=prompt
        )
        return resposta.text
    except Exception as erro:
        return f"Erro de comunicação com a IA: {str(erro)}"