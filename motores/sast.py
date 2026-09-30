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