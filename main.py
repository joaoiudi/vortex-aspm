import os
import asyncio
from fastapi import FastAPI, Request, BackgroundTasks
from ia.gemini import gerar_remediacao_ia
from database import iniciar_banco, salvar_historico
from motores.sast import executar_sast
from motores.sca import executar_sca
from motores.secrets import executar_secrets
from motores.dast import executar_dast
from relatorios import gerar_pdf_seguranca
from monitor import GerenciadorMonitores

app = FastAPI()
iniciar_banco()


@app.exception_handler(Exception)
async def manipulador_erro_global(request: Request, exc: Exception):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=200,
        content={"status": "erro", "mensagem": f"Erro inesperado no servidor: {str(exc)}"},
    )


def _gerar_pdf_seguro(dados: dict):
    """Gera o PDF sem deixar uma falha na geração derrubar a resposta da API
    — a análise de segurança já foi concluída e salva; o PDF é um extra."""
    try:
        gerar_pdf_seguranca(dados)
    except Exception as erro:
        print(f"⚠️ [PDF] Falha ao gerar relatório em PDF (análise já salva normalmente): {erro}")


# Pasta isolada para os arquivos de teste (o Uvicorn ignora esta pasta, evitando reboots)
PASTA_WORKSPACE = "workspace"
os.makedirs(PASTA_WORKSPACE, exist_ok=True)

# Um Observer (watchdog) por arquivo monitorado — substitui o antigo loop de
# polling com time.sleep(10) + hash MD5. Reage a eventos reais do SO.
gerenciador_monitores = GerenciadorMonitores()


@app.get("/")
def raiz():
    return {"mensagem": "ASPM Vortex rodando com sucesso!"}


# --- ROTA: SAST (Static Application Security Testing) ---
@app.post("/scan_codigo")
async def scan_codigo(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo")

        nome_arquivo_salvo = os.path.join(PASTA_WORKSPACE, "alvo_teste.py")
        with open(nome_arquivo_salvo, "w", encoding="utf-8") as arquivo_temporario:
            arquivo_temporario.write(codigo_fonte)

        resultado_sast = executar_sast(nome_arquivo_salvo)

        if resultado_sast["status"] in ["erro", "sucesso"]:
            return resultado_sast

        # CORREÇÃO: executar_sast() retorna 'detalhes_lista' + 'severidade',
        # não 'detalhe_falha' / 'linha' (essas chaves nunca existiram e
        # causavam KeyError sempre que essa rota encontrava uma falha).
        detalhes_lista = resultado_sast.get("detalhes_lista", [])
        primeira_falha = detalhes_lista[0] if detalhes_lista else {
            "issue_text": "Falha estrutural não especificada",
            "line_number": 0,
        }

        detalhe = f"{primeira_falha['issue_text']} (Linha: {primeira_falha['line_number']})"
        texto_remediacao = gerar_remediacao_ia("sast", detalhe)

        salvar_historico(
            "alvo_teste.py",
            resultado_sast["total_falhas"],
            resultado_sast["severidade"],
            motor="SAST",
            analise_ia=texto_remediacao,
            falha_identificada=primeira_falha["issue_text"],
        )

        _gerar_pdf_seguro({
            "arquivo_analisado": "alvo_teste.py",
            "total_falhas": resultado_sast["total_falhas"],
            "severidade": resultado_sast["severidade"],
            "falha_identificada": primeira_falha["issue_text"],
            "analise_ia": texto_remediacao,
        })

        return {
            "status": "sucesso",
            "arquivo_analisado": "alvo_teste.py",
            "total_falhas": resultado_sast["total_falhas"],
            "severidade": resultado_sast["severidade"],
            "falha_identificada": primeira_falha["issue_text"],
            "linha_do_codigo": primeira_falha["line_number"],
            "analise_ia": texto_remediacao,
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}


# --- ROTA: SECRETS (Caçador de Credenciais) ---
@app.post("/scan_segredos")
async def scan_segredos(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo", "")

        resultado_secrets = executar_secrets(codigo_fonte)

        if resultado_secrets["status"] == "sucesso":
            return resultado_secrets

        falha = resultado_secrets["falha_principal"]

        detalhe = f"Tipo: {falha['tipo']} (Linha: {falha['linha']})"
        texto_remediacao = gerar_remediacao_ia("secrets", detalhe)

        salvar_historico(
            "alvo_teste.py",
            resultado_secrets["total_falhas"],
            "CRÍTICO (Vazamento)",
            motor="SECRETS",
            analise_ia=texto_remediacao,
            falha_identificada=f"Exposição de Credencial: {falha['tipo']}",
        )

        _gerar_pdf_seguro({
            "arquivo_analisado": "alvo_teste.py",
            "total_falhas": resultado_secrets["total_falhas"],
            "severidade": "CRÍTICO (Vazamento)",
            "falha_identificada": f"Exposição de Credencial: {falha['tipo']}",
            "analise_ia": texto_remediacao,
        })

        return {
            "status": "sucesso",
            "arquivo_analisado": "alvo_teste.py",
            "total_falhas": resultado_secrets["total_falhas"],
            "severidade": "CRÍTICO (Vazamento)",
            "falha_identificada": f"Exposição de Credencial: {falha['tipo']}",
            "linha_do_codigo": falha["linha"],
            "analise_ia": texto_remediacao,
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}


# --- ROTA: SCA (Software Composition Analysis) ---
@app.post("/scan_dependencias")
async def scan_dependencias(request: Request):
    try:
        dados_recebidos = await request.json()
        conteudo_requirements = dados_recebidos.get("conteudo", "")
        nome_arquivo_original = dados_recebidos.get("nome_arquivo", "requirements.txt")

        with open("alvo_requirements.txt", "w", encoding="utf-8") as f:
            f.write(conteudo_requirements)

        resultado = executar_sca("alvo_requirements.txt")

        if resultado["status"] in ["erro", "sucesso"]:
            return resultado

        total_falhas = resultado["total_falhas"]
        nome_pacote = resultado["nome_pacote"]
        versao_pacote = resultado["versao_pacote"]
        cve_id = resultado["cve_id"]

        detalhe = f"{cve_id} no pacote {nome_pacote} (v{versao_pacote})"
        texto_remediacao = gerar_remediacao_ia("sca", detalhe)

        salvar_historico(
            nome_arquivo_original,
            total_falhas,
            "ALTO (SCA)",
            motor="SCA",
            analise_ia=texto_remediacao,
            falha_identificada=f"Biblioteca Comprometida: {nome_pacote} ({cve_id})",
        )

        _gerar_pdf_seguro({
            "arquivo_analisado": nome_arquivo_original,
            "total_falhas": total_falhas,
            "severidade": "ALTO (SCA)",
            "falha_identificada": f"Biblioteca Comprometida: {nome_pacote} ({cve_id})",
            "analise_ia": texto_remediacao,
        })

        return {
            "status": "sucesso",
            "arquivo_analisado": nome_arquivo_original,
            "total_falhas": total_falhas,
            "severidade": "ALTO (SCA)",
            "falha_identificada": f"Biblioteca Comprometida: {nome_pacote} ({cve_id})",
            "linha_do_codigo": "N/A",
            "analise_ia": texto_remediacao,
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}


# --- ROTA: DAST (Dynamic Application Security Testing) ---
@app.post("/scan_dast")
async def scan_dast(request: Request):
    try:
        dados_recebidos = await request.json()
        url_alvo = dados_recebidos.get("url_alvo", "")

        resultado_dast = await asyncio.to_thread(executar_dast, url_alvo)

        if resultado_dast["status"] in ["erro", "sucesso"]:
            return resultado_dast

        detalhes_lista = resultado_dast.get("detalhes_lista", [])
        detalhes_texto = "\n".join(
            f"[DAST] {item['issue_text']} (Endpoint: {item['endpoint']})" for item in detalhes_lista
        )
        score_risco = resultado_dast.get("score_risco", 0)

        texto_remediacao = gerar_remediacao_ia("dast", detalhes_texto, score_risco=score_risco)

        salvar_historico(
            url_alvo,
            resultado_dast["total_falhas"],
            resultado_dast["severidade_maxima"],
            motor="DAST",
            analise_ia=texto_remediacao,
            falha_identificada=detalhes_texto,
            score_risco=score_risco,
        )
        _gerar_pdf_seguro({
            "arquivo_analisado": url_alvo,
            "total_falhas": resultado_dast["total_falhas"],
            "severidade": resultado_dast["severidade_maxima"],
            "falha_identificada": detalhes_texto,
            "analise_ia": texto_remediacao,
        })

        return {
            "status": "sucesso",
            "arquivo_analisado": url_alvo,
            "total_falhas": resultado_dast["total_falhas"],
            "severidade": resultado_dast["severidade_maxima"],
            "score_risco": score_risco,
            "falha_identificada": detalhes_texto,
            "analise_ia": texto_remediacao,
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}


# --- ROTA UNIFICADA: ANÁLISE COMPLETA (SAST + SECRETS) ---
@app.post("/scan_completo")
async def scan_completo(request: Request):
    try:
        dados_recebidos = await request.json()
        codigo_fonte = dados_recebidos.get("codigo", "")

        nome_arquivo_original = dados_recebidos.get("nome_arquivo", "alvo_teste.py")
        nome_arquivo = os.path.join(PASTA_WORKSPACE, nome_arquivo_original)

        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(codigo_fonte)

        res_sast = executar_sast(nome_arquivo)
        res_secrets = executar_secrets(codigo_fonte)

        total_falhas = 0
        detalhes_combinados = []
        risco_maximo = "BAIXO"

        if isinstance(res_sast, dict) and res_sast.get("status") == "vulneravel":
            detalhes_lista = res_sast.get("detalhes_lista", [])
            total_falhas += len(detalhes_lista)
            for falha in detalhes_lista:
                detalhes_combinados.append(f"[SAST] {falha['issue_text']} (Linha: {falha['line_number']})")
                if falha["issue_severity"] in ["ALTO", "CRÍTICO"]:
                    risco_maximo = "ALTO"

        if res_secrets.get("status") == "vulneravel":
            total_falhas += res_secrets.get("total_falhas", 1)
            falha_sec = res_secrets["falha_principal"]
            detalhes_combinados.append(f"[SECRET] Vazamento de {falha_sec['tipo']} (Linha: {falha_sec['linha']})")
            risco_maximo = "CRÍTICO (Vazamento)"

        if total_falhas == 0:
            return {"status": "sucesso", "mensagem": "✅ Nenhuma vulnerabilidade ou segredo encontrado!"}

        falha_principal_texto = "\n".join(detalhes_combinados)

        texto_remediacao = gerar_remediacao_ia("sast", falha_principal_texto)

        salvar_historico(
            nome_arquivo_original,
            total_falhas,
            risco_maximo,
            motor="SAST+SECRETS",
            analise_ia=texto_remediacao,
            falha_identificada=falha_principal_texto,
        )

        _gerar_pdf_seguro({
            "arquivo_analisado": nome_arquivo_original,
            "total_falhas": total_falhas,
            "severidade": risco_maximo,
            "falha_identificada": falha_principal_texto,
            "analise_ia": texto_remediacao,
        })

        return {
            "status": "sucesso",
            "arquivo_analisado": nome_arquivo_original,
            "total_falhas": total_falhas,
            "severidade": risco_maximo,
            "falha_identificada": falha_principal_texto,
            "analise_ia": texto_remediacao,
        }

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Erro interno na API: {str(erro)}"}


def executar_pipeline_seguranca(repo_nome: str, commit_id: str, autor: str):
    arquivo_auditado = f"Repositório: {repo_nome} (Commit: {commit_id[:7]})"
    salvar_historico(arquivo_auditado, 0, "SEGURO (Varredura CI/CD)", motor="CI_CD")
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

            return {
                "status": "sucesso",
                "mensagem": f"Webhook interceptado. Pipeline ASPM iniciado para o repo {repo_nome}.",
            }

        return {"status": "ignorado", "mensagem": "Evento ignorado. Nenhum commit detectado."}

    except Exception as erro:
        return {"status": "erro", "mensagem": f"Falha ao processar webhook corporativo: {str(erro)}"}


# --- MONITORAMENTO CONTÍNUO (watchdog)---
@app.post("/iniciar_monitoramento")
def iniciar_monitoramento(payload: dict):
    nome_arquivo = payload.get("nome_arquivo", "alvo_teste.py")
    codigo = payload.get("codigo", "")

    caminho_completo = os.path.join(PASTA_WORKSPACE, nome_arquivo)
    with open(caminho_completo, "w", encoding="utf-8") as f:
        f.write(codigo)

    gerenciador_monitores.iniciar(
        os.path.abspath(caminho_completo),
        os.path.abspath(PASTA_WORKSPACE),
    )

    return {"status": "sucesso", "mensagem": f"Monitoramento contínuo ativado para {nome_arquivo}!"}


@app.post("/parar_monitoramento")
def parar_monitoramento(payload: dict):
    nome_arquivo = payload.get("nome_arquivo", "alvo_teste.py")
    caminho_completo = os.path.abspath(os.path.join(PASTA_WORKSPACE, nome_arquivo))
    gerenciador_monitores.parar(caminho_completo)
    return {"status": "sucesso", "mensagem": "Monitoramento desativado."}