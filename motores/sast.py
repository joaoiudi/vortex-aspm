import json
import re

def executar_sast(caminho_arquivo: str = "alvo_teste.py") -> dict:
    """
    Motor SAST nativo em Python para análise estática de código e detecção de padrões inseguros,
    totalmente compatível com qualquer versão do Python sem conflitos de plugins.
    """
    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
            
        falhas_encontradas = []
        
        # Regras de análise estática de código (padrões perigosos comuns)
        regras_inseguras = [
            {
                "padrao": r"\bexec\s*\(",
                "texto": "Uso da função 'exec()', permitindo a execução arbitrária de código dinâmico.",
                "severidade": "ALTO",
                "teste_id": "B102"
            },
            {
                "padrao": r"\beval\s*\(",
                "texto": "Uso da função 'eval()', vulnerável a injeção de código.",
                "severidade": "ALTO",
                "teste_id": "B307"
            },
            {
                "padrao": r"subprocess\..*shell\s*=\s*True",
                "texto": "Uso de subprocesso com 'shell=True', vulnerável a Command Injection.",
                "severidade": "ALTO",
                "teste_id": "B602"
            },
            {
                "padrao": r"\bpickle\.load",
                "texto": "Desserialização insegura utilizando 'pickle', passível de execução remota de código.",
                "severidade": "MÉDIO",
                "teste_id": "B301"
            },
            {
                "padrao": r"MD5|SHA1",
                "texto": "Uso de algoritmo de hash criptográfico obsoleto ou inseguro.",
                "severidade": "BAIXO",
                "teste_id": "B303"
            }
        ]

        for num_linha, linha_texto in enumerate(linhas, start=1):
            for regra in regras_inseguras:
                if re.search(regra["padrao"], linha_texto):
                    falhas_encontradas.append({
                        "issue_text": regra["texto"],
                        "issue_severity": regra["severidade"],
                        "line_number": num_linha,
                        "test_id": regra["teste_id"]
                    })

        if not falhas_encontradas:
            return {"status": "sucesso", "mensagem": "✅ Nenhuma vulnerabilidade estrutural encontrada!"}
            
        falha_principal = falhas_encontradas[0]
        
        return {
            "status": "vulneravel",
            "total_falhas": len(falhas_encontradas),
            "severidade": falha_principal["issue_severity"],
            "detalhe_falha": falha_principal["issue_text"],
            "linha": falha_principal["line_number"],
            "teste_id": falha_principal["test_id"]
        }
        
    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno no motor SAST: {str(erro)}"}