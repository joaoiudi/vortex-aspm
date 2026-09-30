import streamlit as st
import requests
import sqlite3
import pandas as pd
import os
import html
import threading
import time
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="Vortex ASPM", page_icon="🛡️", layout="wide")

# --- CSS ---
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&family=Inter:wght@400;500;600&display=swap');

    :root {
        --vx-bg: #0A0E14;
        --vx-surface: #131920;
        --vx-border: #232B36;
        --vx-text: #E6EDF3;
        --vx-text-muted: #8B98A5;
        --vx-accent: #00E5C7;
        --vx-critico: #FF4757;
        --vx-alto: #FF9F43;
        --vx-medio: #FFD43B;
        --vx-baixo: #51CF66;
    }

    .block-container {
        max-width: 90% !important;
        padding-top: 2rem !important;
    }

    [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: var(--vx-bg);
    }

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        color: var(--vx-text);
    }

    h1, h2, h3, h4 {
        font-family: 'JetBrains Mono', monospace !important;
        letter-spacing: -0.01em;
    }

    .vx-header {
        display: flex;
        align-items: baseline;
        gap: 0.75rem;
        border-bottom: 2px solid var(--vx-accent);
        padding-bottom: 0.9rem;
        margin-bottom: 1.6rem;
    }
    .vx-header .vx-logo {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        font-size: 1.9rem;
        color: var(--vx-text);
        letter-spacing: -0.02em;
    }
    .vx-header .vx-logo span { color: var(--vx-accent); }
    .vx-header .vx-tagline {
        font-family: 'Inter', sans-serif;
        color: var(--vx-text-muted);
        font-size: 0.92rem;
    }

    .vx-metric {
        background-color: var(--vx-surface);
        border: 1px solid var(--vx-border);
        border-left: 3px solid var(--vx-accent);
        border-radius: 6px;
        padding: 0.9rem 1rem;
        min-height: 92px;
    }
    .vx-metric-label {
        color: var(--vx-text-muted);
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.35rem;
    }
    .vx-metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.35rem;
        font-weight: 700;
        color: var(--vx-text);
        line-height: 1.3;
        overflow-wrap: anywhere;
        word-break: break-word;
    }

    .stButton > button {
        border-radius: 6px;
        border: 1px solid var(--vx-border);
        font-family: 'JetBrains Mono', monospace;
        font-weight: 500;
    }
    .stButton > button:hover {
        border-color: var(--vx-accent);
        color: var(--vx-accent);
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--vx-border);
        border-radius: 6px;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0px 0px;
        padding-top: 10px;
        padding-bottom: 10px;
    }

    [data-testid="stFileUploaderDropzoneInstructions"] small {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "em_varredura" not in st.session_state:
    st.session_state.em_varredura = False

# O autorefresh só roda se NÃO estiver executando uma varredura manual no momento.
# Se o monitoramento contínuo estiver ativo, atualiza a cada 4s; senão a cada 10s.
if not st.session_state.em_varredura:
    intervalo_refresh = 4000 if st.session_state.get("monitorando", False) else 10000
    st_autorefresh(interval=intervalo_refresh, limit=None, key="vortex_auto_refresh")

st.markdown(
    """
    <div class="vx-header">
        <span class="vx-logo">🛡️ VORTEX<span>_ASPM</span></span>
        <span class="vx-tagline">Application Security Posture Management</span>
    </div>
    """,
    unsafe_allow_html=True,
)

if "mensagem_scan" not in st.session_state:
    st.session_state.mensagem_scan = None
if "mensagem_dast" not in st.session_state:
    st.session_state.mensagem_dast = None
if "mensagem_sca" not in st.session_state:
    st.session_state.mensagem_sca = None
if "resultado_direto_sast" not in st.session_state:
    st.session_state.resultado_direto_sast = None
if "resultado_direto_sca" not in st.session_state:
    st.session_state.resultado_direto_sca = None
if "resultado_direto_dast" not in st.session_state:
    st.session_state.resultado_direto_dast = None
if "aba_ativa" not in st.session_state:
    st.session_state.aba_ativa = "🔍 Código (SAST/Secrets)"

def _decodificar_upload(arquivo_upado) -> str:
    """Decodifica o conteúdo de um upload com fallback seguro — evita que um
    arquivo salvo em encoding diferente (ex: Windows-1252) derrube a página inteira."""
    bruto = arquivo_upado.getvalue()
    try:
        return bruto.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return bruto.decode("latin-1")
        except Exception:
            return bruto.decode("utf-8", errors="replace")


def _executar_requisicao_com_status(url: str, payload: dict, titulo_status: str, etapas: list, timeout: int = 90):
    """Executa a requisição exibindo em tempo real cada etapa do pipeline (incluindo geração de IA) via st.status."""
    st.session_state.em_varredura = True
    resultado = {"resposta": None, "erro": None, "concluido": False}

    def _tarefa():
        try:
            res = requests.post(url, json=payload, timeout=timeout)
            resultado["resposta"] = res
        except Exception as e:
            resultado["erro"] = e
        finally:
            resultado["concluido"] = True

    thread = threading.Thread(target=_tarefa)
    thread.start()

    with st.status(titulo_status, expanded=True) as status_box:
        indice = 0
        etapa_placeholder = st.empty()
        while not resultado["concluido"]:
            msg = etapas[min(indice, len(etapas) - 1)]
            etapa_placeholder.markdown(f"⏳ **{msg}**")
            time.sleep(1.5)
            indice += 1

        if resultado["erro"]:
            status_box.update(label="❌ Erro na comunicação com o backend", state="error", expanded=True)
            st.session_state.em_varredura = False
            raise resultado["erro"]

        status_box.update(label="✅ Varredura e Remediação Concluídas!", state="complete", expanded=False)
        st.session_state.em_varredura = False
        return resultado["resposta"]


def _exibir(mensagem: dict):
    if not mensagem:
        return
    tipo = mensagem.get("tipo", "info")
    texto = mensagem.get("texto", "")
    if tipo == "success":
        st.success(texto)
    elif tipo == "error":
        st.error(texto)
    elif tipo == "warning":
        st.warning(texto)
    else:
        st.info(texto)


def formatar_origem(motor: str) -> str:
    ICONES_MOTOR = {
        "MANUAL": "🖐️ Manual",
        "SAST": "🖐️ Manual (SAST)",
        "SECRETS": "🖐️ Manual (Secrets)",
        "SCA": "🖐️ Manual (SCA)",
        "SAST+SECRETS": "🖐️ Manual (Completo)",
        "MONITOR": "🤖 Monitoramento Contínuo",
        "CI_CD": "🔗 Webhook CI/CD",
        "DAST": "🌐 Varredura Dinâmica (DAST)",
    }
    return ICONES_MOTOR.get(str(motor), f"❓ {motor}")


def _metrica(coluna, label: str, valor: str):
    coluna.markdown(
        f"""
        <div class="vx-metric">
            <div class="vx-metric-label">{html.escape(label)}</div>
            <div class="vx-metric-value">{html.escape(str(valor))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _linha_resultado(dados: dict, motor_padrao: str, arquivo_padrao: str) -> dict:
    """Constrói uma linha no mesmo formato de uma linha do banco, a partir
    da resposta direta da API — usada para exibição imediata pós-ação."""
    return {
        "id": -1,
        "total_falhas": dados.get("total_falhas", 0),
        "risco_maximo": dados.get("severidade", "BAIXO"),
        "arquivo": dados.get("arquivo_analisado", arquivo_padrao),
        "falha_identificada": dados.get("falha_identificada", ""),
        "motor": motor_padrao,
        "analise_ia": dados.get("analise_ia", ""),
        "score_risco": dados.get("score_risco"),
    }


def exibir_dashboard(df_alvo, resultado_direto=None):
    """Renderiza o relatório formatado com IA. Se resultado_direto for
    fornecido, usa ele (resposta fresca da API); senão cai para a linha
    mais recente do cache do banco."""
    if resultado_direto:
        ultimo = resultado_direto
    elif not df_alvo.empty:
        ultimo = df_alvo.iloc[0]
    else:
        st.info("Nenhum relatório processado para este motor ainda.")
        return

    total_f = ultimo.get("total_falhas", 0)
    risco_m = ultimo.get("risco_maximo", "CRÍTICO")
    arquivo_n = ultimo.get("arquivo", "alvo")
    falha_id = ultimo.get("falha_identificada", "")
    origem = ultimo.get("motor", "MANUAL")
    analise_ia = str(ultimo.get("analise_ia", ""))
    score_risco = ultimo.get("score_risco")

    if not analise_ia or analise_ia.strip() == "" or analise_ia == "nan" or analise_ia == "None":
        try:
            conexao_temp = sqlite3.connect("banco_aspm.db", timeout=10)
            df_ia = pd.read_sql_query(
                f"SELECT analise_ia FROM historico_scans WHERE id = {ultimo['id']} AND analise_ia IS NOT NULL AND analise_ia != ''",
                conexao_temp,
            )
            conexao_temp.close()
            if not df_ia.empty:
                analise_ia = df_ia.iloc[0]["analise_ia"]
        except Exception:
            pass

    if score_risco is not None and pd.notna(score_risco):
        score_int = int(score_risco)
        if score_int >= 75:
            cor_score, rotulo_score = "#FF4757", "CRÍTICO"
        elif score_int >= 50:
            cor_score, rotulo_score = "#FF9F43", "ALTO"
        elif score_int >= 25:
            cor_score, rotulo_score = "#FFD43B", "MODERADO"
        else:
            cor_score, rotulo_score = "#51CF66", "BAIXO"

        st.markdown(
            f"""
            <div style="background-color: var(--vx-surface); border: 1px solid var(--vx-border);
                        border-left: 4px solid {cor_score}; border-radius: 6px; padding: 1rem 1.2rem;
                        margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--vx-text-muted);
                                text-transform: uppercase; letter-spacing: 0.05em;">Score de Risco Agregado</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; color: {cor_score};">
                        {score_int}<span style="font-size: 1rem; color: var(--vx-text-muted);">/100</span>
                    </div>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: {cor_score};
                            border: 1px solid {cor_score}; border-radius: 4px; padding: 0.3rem 0.8rem;">
                    {rotulo_score}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    col1, col2, col3, col4 = st.columns(4)
    _metrica(col1, "Total de Falhas", int(total_f) if pd.notna(total_f) else 0)
    _metrica(col2, "Risco Máximo", str(risco_m))
    _metrica(col3, "Alvo", str(arquivo_n))
    _metrica(col4, "Motor", formatar_origem(origem))

    st.markdown("<br>", unsafe_allow_html=True)

    falhas_lista = [f.strip() for f in str(falha_id).split('\n') if f.strip()]
    if len(falhas_lista) > 1:
        texto_falhas = "🚨 **Falhas Detectadas:**\n" + "\n".join([f"* {falha}" for falha in falhas_lista])
        st.error(texto_falhas)
    elif falhas_lista:
        st.error(f"🚨 Falhas Detectadas: **{str(falha_id)}**")

    st.markdown("### 🤖 Remediação Sugerida (IA)")
    if analise_ia and str(analise_ia).strip() != "" and str(analise_ia) != "None":
        st.markdown(str(analise_ia))
    else:
        st.info("Aguardando processamento da IA para este alerta...")

    st.markdown("<br>", unsafe_allow_html=True)
    if os.path.exists("relatorio_seguranca.pdf"):
        with open("relatorio_seguranca.pdf", "rb") as arquivo_pdf:
            st.download_button(
                label="📥 Baixar Relatório Executivo em PDF",
                data=arquivo_pdf,
                file_name=f"relatorio_{arquivo_n}.pdf",
                mime="application/pdf",
                use_container_width=True,
                key=f"pdf_btn_{origem}_{ultimo.get('id', 0)}"
            )


# --- BUSCA DE DADOS (DB) ---
try:
    conexao = sqlite3.connect("banco_aspm.db", timeout=10)
    ultimo_id_no_banco = conexao.execute("SELECT COALESCE(MAX(id), 0) FROM historico_scans").fetchone()[0]
    conexao.close()
except Exception:
    ultimo_id_no_banco = None

if "ultimo_id_renderizado" not in st.session_state:
    st.session_state.ultimo_id_renderizado = None

houve_novo_registro = (
    ultimo_id_no_banco is not None and ultimo_id_no_banco != st.session_state.ultimo_id_renderizado
)

if houve_novo_registro or "cache_df_historico" not in st.session_state:
    try:
        conexao = sqlite3.connect("banco_aspm.db", timeout=10)
        st.session_state.cache_df_historico = pd.read_sql_query(
            "SELECT * FROM historico_scans ORDER BY id DESC", conexao
        )
        conexao.close()
        st.session_state.ultimo_id_renderizado = ultimo_id_no_banco
    except Exception:
        pass

df = st.session_state.get("cache_df_historico", pd.DataFrame())

# PAINEL DE COMANDOS E DASHBOARDS ISOLADOS
NOMES_ABAS = ["🔍 Código (SAST/Secrets)", "📦 Dependências (SCA)", "🌐 Dinâmico (DAST)"]
tab_sast, tab_sca, tab_dast = st.tabs(
    NOMES_ABAS,
    default=st.session_state.aba_ativa,
    key="abas_principais",
)

# ----- ABA 1: SAST/SECRETS -----
with tab_sast:
    st.caption("Analisa código fonte em busca de falhas estruturais e vazamento de credenciais.")

    arquivo_upado = st.file_uploader("Faça o upload do arquivo Python (.py)", type=["py"])
    if "monitorando" not in st.session_state:
        st.session_state.monitorando = False

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🚀 Executar Varredura Única", use_container_width=True):
            if arquivo_upado is not None:
                codigo_lido = _decodificar_upload(arquivo_upado)
                payload = {"nome_arquivo": arquivo_upado.name, "codigo": codigo_lido}
                etapas_sast = [
                    "Enviando código-fonte para a plataforma...",
                    "Executando varreduras de SAST e detecção de credenciais expostas...",
                    "Consultando Google Gemini para análise de vulnerabilidades estruturais...",
                    "IA gerando plano de remediação estruturado e código corrigido...",
                    "Compilando métricas de postura e consolidando histórico..."
                ]
                try:
                    resposta = _executar_requisicao_com_status(
                        "http://backend:8000/scan_completo",
                        payload,
                        "🛡️ Executando Varredura e Remediação com IA...",
                        etapas_sast,
                        timeout=90,
                    )
                    dados = resposta.json()
                    if dados.get("status") == "sucesso":
                        st.session_state.mensagem_scan = {"tipo": "success", "texto": "Varredura concluída com sucesso!"}
                        st.session_state.resultado_direto_sast = _linha_resultado(
                            dados, "SAST+SECRETS", arquivo_upado.name
                        )
                        try:
                            conexao_imediata = sqlite3.connect("banco_aspm.db", timeout=10)
                            st.session_state.cache_df_historico = pd.read_sql_query(
                                "SELECT * FROM historico_scans ORDER BY id DESC", conexao_imediata
                            )
                            conexao_imediata.close()
                        except Exception:
                            pass
                    else:
                        st.session_state.mensagem_scan = {"tipo": "error", "texto": f"Erro do motor: {dados.get('mensagem')}"}
                except Exception as e:
                    st.session_state.mensagem_scan = {"tipo": "error", "texto": f"Erro de API: {e}"}
                finally:
                    st.session_state.em_varredura = False
                st.rerun()
            else:
                st.session_state.mensagem_scan = {"tipo": "warning", "texto": "⚠️ Faça o upload de um arquivo .py."}
                st.rerun()

    with col_btn2:
        if not st.session_state.monitorando:
            if st.button("👁️ Ativar Monitoramento Contínuo", use_container_width=True):
                if arquivo_upado is not None:
                    payload = {"nome_arquivo": arquivo_upado.name, "codigo": _decodificar_upload(arquivo_upado)}
                    requests.post("http://backend:8000/iniciar_monitoramento", json=payload, timeout=30)
                    st.session_state.monitorando = True
                    st.session_state.resultado_direto_sast = None
                    st.rerun()
                else:
                    st.session_state.mensagem_scan = {"tipo": "warning", "texto": "⚠️ Envie um arquivo para monitorar."}
                    st.rerun()
        else:
            if st.button("⏹️ Parar Monitoramento", use_container_width=True, type="primary"):
                if arquivo_upado is not None:
                    requests.post("http://backend:8000/parar_monitoramento", json={"nome_arquivo": arquivo_upado.name}, timeout=30)
                st.session_state.monitorando = False
                st.rerun()

    _exibir(st.session_state.mensagem_scan)
    if st.session_state.monitorando:
        st.info("🟢 **Monitoramento Contínuo Ativo:** O Vortex está vigiando este arquivo em segundo plano.")

    st.divider()
    st.markdown("### 📊 Relatório de Segurança (Código)")
    df_sast = df[df['motor'].isin(['SAST+SECRETS', 'MONITOR', 'SAST', 'SECRETS'])] if not df.empty else pd.DataFrame()
    exibir_dashboard(df_sast, resultado_direto=st.session_state.resultado_direto_sast)


# ----- ABA 2: SCA -----
with tab_sca:
    st.caption("Analisa dependências do projeto (requirements.txt) em busca de pacotes com vulnerabilidades conhecidas (CVEs).")

    arquivo_requirements = st.file_uploader("Faça o upload do requirements.txt", type=["txt"], key="upload_sca")

    if st.button("📦 Executar Varredura SCA", use_container_width=True):
        if arquivo_requirements is not None:
            conteudo_requirements = _decodificar_upload(arquivo_requirements)
            etapas_sca = [
                "Lendo manifesto de dependências requirements.txt...",
                "Consultando base de vulnerabilidades conhecidas (OSV/CVEs)...",
                "IA gerando recomendações de atualização para pacotes vulneráveis...",
                "Compilando relatório de auditoria de dependências..."
            ]
            try:
                resposta = _executar_requisicao_com_status(
                    "http://backend:8000/scan_dependencias",
                    {"conteudo": conteudo_requirements, "nome_arquivo": arquivo_requirements.name},
                    "📦 Auditando Dependências (SCA)...",
                    etapas_sca,
                    timeout=90,
                )
                dados = resposta.json()
                if dados.get("status") == "sucesso" and "total_falhas" not in dados:
                    st.session_state.mensagem_sca = {"tipo": "success", "texto": dados.get("mensagem", "Nenhuma falha!")}
                    st.session_state.resultado_direto_sca = None
                elif dados.get("status") == "sucesso":
                    st.session_state.mensagem_sca = {"tipo": "success", "texto": "Varredura SCA concluída!"}
                    st.session_state.resultado_direto_sca = _linha_resultado(
                        dados, "SCA", arquivo_requirements.name
                    )
                    try:
                        conexao_imediata = sqlite3.connect("banco_aspm.db", timeout=10)
                        st.session_state.cache_df_historico = pd.read_sql_query(
                            "SELECT * FROM historico_scans ORDER BY id DESC", conexao_imediata
                        )
                        conexao_imediata.close()
                    except Exception:
                        pass
                else:
                    st.session_state.mensagem_sca = {"tipo": "error", "texto": f"Erro do motor SCA: {dados.get('mensagem')}"}
            except Exception as e:
                st.session_state.mensagem_sca = {"tipo": "error", "texto": f"Erro de API: {e}"}
            finally:
                st.session_state.em_varredura = False
            st.session_state.aba_ativa = "📦 Dependências (SCA)"
            st.rerun()
        else:
            st.session_state.mensagem_sca = {"tipo": "warning", "texto": "⚠️ Faça o upload de um requirements.txt."}
            st.session_state.aba_ativa = "📦 Dependências (SCA)"
            st.rerun()

    _exibir(st.session_state.get("mensagem_sca"))

    st.divider()
    st.markdown("### 📊 Relatório de Segurança (Dependências)")
    df_sca = df[df['motor'] == 'SCA'] if not df.empty else pd.DataFrame()
    exibir_dashboard(df_sca, resultado_direto=st.session_state.resultado_direto_sca)


# ----- ABA 3: DAST -----
with tab_dast:
    st.caption("Testa uma aplicação **em execução** via HTTP — headers de segurança, endpoints sensíveis expostos e injeção refletida.")

    url_alvo_dast = st.text_input("URL do alvo", value="http://backend:8000")

    if st.button("🎯 Executar Varredura DAST", use_container_width=True):
        etapas_dast = [
            f"Conectando à aplicação em {url_alvo_dast}...",
            "Inspecionando cabeçalhos de segurança HTTP (CSP, HSTS, X-Frame)...",
            "Avaliando flags de sessão em cookies e vazamento de versão do servidor...",
            "IA analisando superfície de ataque dinâmico e calculando score de risco..."
        ]
        try:
            resposta = _executar_requisicao_com_status(
                "http://backend:8000/scan_dast",
                {"url_alvo": url_alvo_dast},
                f"🌐 Executando Varredura Dinâmica em {url_alvo_dast}...",
                etapas_dast,
                timeout=120,
            )
            dados = resposta.json()
            if dados.get("status") == "sucesso" and "total_falhas" not in dados:
                st.session_state.mensagem_dast = {"tipo": "success", "texto": dados.get("mensagem", "Nenhuma falha!")}
                st.session_state.resultado_direto_dast = None
            elif dados.get("status") == "sucesso":
                st.session_state.mensagem_dast = {"tipo": "success", "texto": "Varredura DAST concluída!"}
                st.session_state.resultado_direto_dast = _linha_resultado(
                    dados, "DAST", url_alvo_dast
                )
                try:
                    conexao_imediata = sqlite3.connect("banco_aspm.db", timeout=10)
                    st.session_state.cache_df_historico = pd.read_sql_query(
                        "SELECT * FROM historico_scans ORDER BY id DESC", conexao_imediata
                    )
                    conexao_imediata.close()
                except Exception:
                    pass
            else:
                st.session_state.mensagem_dast = {"tipo": "error", "texto": f"Erro do motor DAST: {dados.get('mensagem')}"}
        except Exception as e:
            st.session_state.mensagem_dast = {"tipo": "error", "texto": f"Erro de API: {e}"}
        finally:
            st.session_state.em_varredura = False
        st.session_state.aba_ativa = "🌐 Dinâmico (DAST)"
        st.rerun()

    _exibir(st.session_state.mensagem_dast)

    st.divider()
    st.markdown("### 📊 Relatório de Segurança (Dinâmico)")
    df_dast = df[df['motor'] == 'DAST'] if not df.empty else pd.DataFrame()
    exibir_dashboard(df_dast, resultado_direto=st.session_state.resultado_direto_dast)


# PAINEL GLOBAL: HISTÓRICO
st.divider()
st.subheader("📈 Gestão de Postura (Histórico Completo)")

if not df.empty:
    col_grafico, col_tabela = st.columns([1.5, 1.5])

    with col_grafico:
        st.markdown("**Evolução de Vulnerabilidades**")
        df_grafico = df.copy()
        df_grafico['data_hora'] = pd.to_datetime(df_grafico['data_hora'])
        df_grafico.set_index('data_hora', inplace=True)
        st.line_chart(df_grafico['total_falhas'], use_container_width=True)

        st.markdown("**Origem dos Eventos**")
        contagem_origem = df['motor'].fillna("MANUAL").apply(formatar_origem).value_counts()
        st.bar_chart(contagem_origem, use_container_width=True)

    with col_tabela:
        st.markdown("**Últimos Registros**")
        df_tabela = df[["data_hora", "arquivo", "total_falhas", "risco_maximo", "motor"]].copy()
        df_tabela["motor"] = df_tabela["motor"].fillna("MANUAL").apply(formatar_origem)
        df_tabela = df_tabela.rename(columns={
            "data_hora": "Data/Hora",
            "arquivo": "Alvo",
            "total_falhas": "Falhas",
            "risco_maximo": "Risco",
            "motor": "Origem",
        })
        st.dataframe(
            df_tabela,
            hide_index=True,
            use_container_width=True,
            column_config={
                "Data/Hora": st.column_config.TextColumn(width="small"),
                "Alvo": st.column_config.TextColumn(width="medium"),
                "Falhas": st.column_config.NumberColumn(width="small"),
                "Risco": st.column_config.TextColumn(width="medium"),
                "Origem": st.column_config.TextColumn(width="medium"),
            },
        )
else:
    st.info("Nenhum registro encontrado no histórico.")