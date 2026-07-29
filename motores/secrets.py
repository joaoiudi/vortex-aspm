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