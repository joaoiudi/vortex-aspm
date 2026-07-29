import streamlit as st
import requests
import sqlite3
import pandas as pd
import os

st.set_page_config(page_title="Vortex ASPM", page_icon="🛡️", layout="centered")

# Injeção de CSS para alargar o container central
st.markdown(
    """
    <style>
    .block-container {
        max-width: 1000px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ Vortex ASPM")
st.markdown("Plataforma de **Application Security Posture Management** com IA Integrada.")

st.divider()

st.subheader("🔍 Motores de Auditoria")

# Cria duas abas separadas
aba1, aba2 = st.tabs(["SAST (Código-Fonte)", "SCA (Dependências)"])

# --- ABA 1: Análise Completa de Código (SAST + Secrets) ---
with aba1:
    arquivo_upado = st.file_uploader("Faça o upload do arquivo Python (.py)", type=["py"])
    
    if st.button("Iniciar Varredura Completa 🚀", use_container_width=True):
        if arquivo_upado is not None:
            codigo_lido = arquivo_upado.getvalue().decode("utf-8")
            payload = {"codigo": codigo_lido}
            
            with st.spinner("Executando motores de segurança e consultando a IA..."):
                try:
                    resposta = requests.post("http://127.0.0.1:8000/scan_completo", json=payload)
                    dados = resposta.json()
                    
                    if dados.get("status") == "sucesso":
                        if "mensagem" in dados:
                            st.success(f"✅ {dados['mensagem']}")
                        else:
                            st.markdown("### 📊 Relatório de Segurança Unificado")
                            
                            # 3 colunas limpas e sem cortar palavras
                            col1, col2, col3 = st.columns(3)
                            col1.metric(label="Total de Falhas", value=dados.get("total_falhas", 0))
                            col2.metric(label="Risco Máximo", value="CRÍTICO" if "CRÍTICO" in str(dados.get("severidade", "")) else dados.get("severidade", "ALTO"))
                            col3.metric(label="Arquivo", value=dados.get("arquivo_analisado", "alvo_teste.py"))
                            
                            st.divider()
                            st.error(f"🚨 Falhas Detectadas: **{dados['falha_identificada']}**")
                            st.markdown("### 🤖 Remediação Sugerida (IA)")
                            st.markdown(dados["analise_ia"])
                            st.divider()
                            
                            if os.path.exists("relatorio_seguranca.pdf"):
                                with open("relatorio_seguranca.pdf", "rb") as arquivo_pdf:
                                    st.download_button(
                                        label="📥 Baixar Relatório Executivo em PDF",
                                        data=arquivo_pdf,
                                        file_name="relatorio_aspm_vortex.pdf",
                                        mime="application/pdf",
                                        use_container_width=True
                                    )
                    else:
                        st.error(f"Erro do motor: {dados.get('mensagem')}")
                        
                except Exception as e:
                    st.error(f"Erro de comunicação com a API: {e}")
        else:
            st.warning("⚠️ Faça o upload de um arquivo .py.")

# --- ABA 2: O Motor SCA ---
with aba2:
    arquivo_req = st.file_uploader("Faça o upload do requirements.txt", type=["txt"])
    if st.button("Analisar Dependências 📦", use_container_width=True):
        if arquivo_req is not None:
            with st.spinner("Varrendo banco de dados global de CVEs..."):
                with open("alvo_requirements.txt", "wb") as f:
                    f.write(arquivo_req.getbuffer())
                
                try:
                    resposta_sca = requests.get("http://127.0.0.1:8000/scan_dependencias")
                    dados_sca = resposta_sca.json()
                    
                    if dados_sca.get("status") == "sucesso":
                        if "mensagem" in dados_sca:
                            st.success(f"✅ {dados_sca['mensagem']}")
                        else:
                            st.markdown("### 📊 Relatório de Composição (SCA)")
                            
                            # Tratamento seguro da severidade fora da função metric
                            severidade_sca = dados_sca.get("severidade", "ALTO")
                            risco_formatado = "ALTO" if "ALTO" in str(severidade_sca) else str(severidade_sca)
                            
                            # 3 colunas limpas para a Aba 2
                            col1, col2, col3 = st.columns(3)
                            col1.metric(label="Bibliotecas Vulneráveis", value=dados_sca.get("total_falhas", 1))
                            col2.metric(label="Risco", value=risco_formatado)
                            col3.metric(label="Arquivo", value="requirements.txt")
                            
                            st.divider()
                            st.error(f"🚨 Risco Detectado: **{dados_sca['falha_identificada']}**")
                            st.markdown("### 🤖 Remediação Sugerida (IA)")
                            st.markdown(dados_sca["analise_ia"])
                            
                    else:
                        st.error(f"Erro no backend: {dados_sca.get('mensagem')}")
                except Exception as e:
                    st.error(f"Erro na interface: {e}")
        else:
            st.warning("⚠️ Faça o upload do requirements.txt.")

# --- NOVO: SEÇÃO DE HISTÓRICO E GRÁFICO ---
st.divider()
st.subheader("📈 Gestão de Postura (Evolução)")

try:
    conexao = sqlite3.connect("banco_aspm.db")
    
    # Puxa os dados formatados usando Pandas
    df = pd.read_sql_query("SELECT id, data_hora, arquivo, total_falhas, risco_maximo FROM historico_scans", conexao)
    
    if not df.empty:
        # Cria duas colunas para dividir o espaço visualmente
        col_grafico, col_tabela = st.columns([1.5, 1.5])
        
        with col_grafico:
            st.markdown("**Curva de Vulnerabilidades Encontradas**")
            # Ajusta a data para o gráfico entender a linha do tempo
            df_grafico = df.copy()
            df_grafico['data_hora'] = pd.to_datetime(df_grafico['data_hora'])
            df_grafico.set_index('data_hora', inplace=True)
            
            # Renderiza o gráfico de linha
            st.line_chart(df_grafico['total_falhas'], use_container_width=True)
            
        with col_tabela:
            st.markdown("**Últimos Registros**")
            # Inverte para mostrar o mais recente primeiro na tabela
            df_tabela = df.sort_values(by="id", ascending=False).drop(columns=["id"])
            st.dataframe(df_tabela, hide_index=True, use_container_width=True)
            
    else:
        st.info("Nenhum registro encontrado no histórico. O gráfico aparecerá após o primeiro scan.")
        
    conexao.close()
    
except Exception as e:
    st.warning(f"Erro ao carregar os dados de evolução: {e}")