import subprocess
from fastapi import FastAPI, Request, BackgroundTasks
import json
from ia.gemini import gerar_remediacao_ia
import re
from database import iniciar_banco, salvar_historico
from datetime import datetime
import sys
from motores.sast import executar_sast
from motores.sca import executar_sca
from motores.secrets import executar_secrets
from relatorios import gerar_pdf_seguranca

app = FastAPI()
iniciar_banco()


@app.get("/")
def raiz():
    return {"mensagem": "ASPM Vortex rodando com sucesso!"}

# --- ROTA REFATORADA: SAST (Static Application Security Testing) ---
@app.post("/scan_codigo")
async def scan_codigo(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo")
        
        nome_arquivo_salvo = "alvo_teste.py"
        with open(nome_arquivo_salvo, "w", encoding="utf-8") as arquivo_temporario:
            arquivo_temporario.write(codigo_fonte)
        
        resultado_sast = executar_sast(nome_arquivo_salvo)
        
        if resultado_sast["status"] in ["erro", "sucesso"]:
            return resultado_sast
            
        salvar_historico(nome_arquivo_salvo, resultado_sast["total_falhas"], resultado_sast["severidade"])

        # Chamada da IA estruturada para SAST
        detalhe = f"{resultado_sast['detalhe_falha']} (Linha: {resultado_sast['linha']})"
        texto_remediacao = gerar_remediacao_ia("sast", detalhe)
        
        return {
            "status": "sucesso",
            "arquivo_analisado": nome_arquivo_salvo,
            "total_falhas": resultado_sast["total_falhas"],
            "severidade": resultado_sast["severidade"],
            "falha_identificada": resultado_sast["detalhe_falha"],
            "linha_do_codigo": resultado_sast["linha"],
            "analise_ia": texto_remediacao
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}

# --- ROTA REFATORADA: SECRETS (Caçador de Credenciais Hardcoded) ---
@app.post("/scan_segredos")
async def scan_segredos(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo", "")
        
        resultado_secrets = executar_secrets(codigo_fonte)
        
        if resultado_secrets["status"] == "sucesso":
            return resultado_secrets
            
        falha = resultado_secrets["falha_principal"]
        
        salvar_historico("alvo_teste.py", resultado_secrets["total_falhas"], "CRÍTICO (Vazamento)")

        # Chamada da IA estruturada para Secrets
        detalhe = f"Tipo: {falha['tipo']} (Linha: {falha['linha']})"
        texto_remediacao = gerar_remediacao_ia("secrets", detalhe)
        
        return {
            "status": "sucesso",
            "arquivo_analisado": "alvo_teste.py",
            "total_falhas": resultado_secrets["total_falhas"],
            "severidade": "CRÍTICO (Vazamento)",
            "falha_identificada": f"Exposição de Credencial: {falha['tipo']}",
            "linha_do_codigo": falha["linha"],
            "analise_ia": texto_remediacao
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}
    
# --- ROTA REFATORADA: SCA (Software Composition Analysis) ---
@app.get("/scan_dependencias")
def scan_dependencias():
    try:
        resultado = executar_sca("alvo_requirements.txt")
        
        if resultado["status"] in ["erro", "sucesso"]:
            return resultado
            
        total_falhas = resultado["total_falhas"]
        nome_pacote = resultado["nome_pacote"]
        versao_pacote = resultado["versao_pacote"]
        cve_id = resultado["cve_id"]
        
        salvar_historico("requirements.txt", total_falhas, "ALTO (SCA)")

        # Chamada da IA estruturada em formato de Ticket SCA (CVE + Pacote)
        detalhe = f"{cve_id} no pacote {nome_pacote} (v{versao_pacote})"
        texto_remediacao = gerar_remediacao_ia("sca", detalhe)
        
        return {
            "status": "sucesso",
            "arquivo_analisado": "requirements.txt",
            "total_falhas": total_falhas,
            "severidade": "ALTO (SCA)",
            "falha_identificada": f"Biblioteca Comprometida: {nome_pacote} ({cve_id})",
            "linha_do_codigo": "N/A",
            "analise_ia": texto_remediacao
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}

# --- ROTA UNIFICADA: ANÁLISE COMPLETA (SAST + SECRETS) ---
@app.post("/scan_completo")
async def scan_completo(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo", "")
        
        nome_arquivo = "alvo_teste.py"
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(codigo_fonte)
            
        res_sast = executar_sast(nome_arquivo)
        res_secrets = executar_secrets(codigo_fonte)
        
        total_falhas = 0
        detalhes_combinados = []
        risco_maximo = "BAIXO"
        motor_ia_tipo = "sast"
        
        if res_sast.get("status") == "vulneravel":
            total_falhas += res_sast["total_falhas"]
            detalhes_combinados.append(f"[SAST] {res_sast['detalhe_falha']} (Linha: {res_sast['linha']})")
            risco_maximo = res_sast["severidade"]
            
        if res_secrets.get("status") == "vulneravel":
            total_falhas += res_secrets["total_falhas"]
            falha_sec = res_secrets["falha_principal"]
            detalhes_combinados.append(f"[SECRET] Vazamento de {falha_sec['tipo']} (Linha: {falha_sec['linha']})")
            risco_maximo = "CRÍTICO (Vazamento)"
            motor_ia_tipo = "secrets" # Prioriza o template de secrets se houver vazamento de chave
            
        if total_falhas == 0:
            return {"status": "sucesso", "mensagem": " Nenhuma vulnerabilidade ou segredo encontrado!"}
            
        falha_principal_texto = " | ".join(detalhes_combinados)
        
        salvar_historico(nome_arquivo, total_falhas, risco_maximo)
        
        # Aciona a IA adaptada para o tipo correto de motor
        texto_remediacao = gerar_remediacao_ia(motor_ia_tipo, falha_principal_texto)

        gerar_pdf_seguranca({
            "arquivo_analisado": nome_arquivo,
            "total_falhas": total_falhas,
            "severidade": risco_maximo,
            "falha_identificada": falha_principal_texto,
            "analise_ia": texto_remediacao
        })
        
        return {
            "status": "sucesso",
            "arquivo_analisado": nome_arquivo,
            "total_falhas": total_falhas,
            "severidade": risco_maximo,
            "falha_identificada": falha_principal_texto,
            "analise_ia": texto_remediacao
        }
        
    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}

def executar_pipeline_seguranca(repo_nome: str, commit_id: str, autor: str):
    arquivo_auditado = f"Repositório: {repo_nome} (Commit: {commit_id[:7]})"
    salvar_historico(arquivo_auditado, 0, "SEGURO (Varredura CI/CD)")
    print(f"\n[ASPM AUTÔNOMO] Pipeline executado com sucesso para o código de {autor}!\n")

@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
        
        if "commits" in payload and len(payload["commits"]) > 0:
            repo_nome = payload["repository"]["name"]
            commit_recente = payload["commits"][0]
            commit_id = commit_recente["id"]
            autor = commit_recente["author"]["name"]
            
            background_tasks.add_task(executar_pipeline_seguranca, repo_nome, commit_id, autor)
            
            return {"status": "sucesso", "mensagem": f"Webhook interceptado. Pipeline ASPM iniciado para o repo {repo_nome}."}
        
        return {"status": "ignorado", "mensagem": "Evento ignorado. Nenhum commit detectado."}
        
    except Exception as erro:
        return {"status": "erro", "mensagem": f"Falha ao processar webhook corporativo: {str(erro)}"}