# Vortex ASPM - Plataforma de Segurança Cibernética

## Descrição do Projeto
O Vortex ASPM (Application Security Posture Management) é uma ferramenta de segurança automatizada desenvolvida para o Challenge da PRIDE para o curso de Defesa Cibernética. A plataforma realiza varreduras em código-fonte Python utilizando múltiplos motores de análise estática e integra Inteligência Artificial generativa para fornecer relatórios técnicos e propor remediações imediatas para as vulnerabilidades encontradas.

## Arquitetura e Tecnologias
O sistema foi construído com uma arquitetura de microsserviços desacoplada:
*   **Backend (API):** Desenvolvido em `FastAPI`, responsável pela orquestração dos motores de segurança e comunicação com a IA.
*   **Motores de Análise:**
    *   `Bandit`: Scanner estrutural para identificação de falhas clássicas (ex: criptografia fraca, injeção de comandos).
    *   `Custom Regex Engine`: Motor próprio para detecção de credenciais vazadas (Hardcoded Secrets).
*   **Inteligência Artificial:** Integração com o modelo `Gemini 3.5 Flash Lite` para formulação de respostas de remediação baseadas nas diretrizes do OWASP.
*   **Frontend (Dashboard):** Interface gráfica desenvolvida em `Streamlit` para visualização de métricas e relatórios.

## Pré-requisitos
Certifique-se de ter o Python 3.9+ instalado em seu ambiente. As bibliotecas necessárias para a execução do projeto são:

*   fastapi
*   uvicorn
*   streamlit
*   requests
*   bandit
*   google-genai

## Como Executar a Plataforma

Para garantir o funcionamento correto, o backend e o frontend devem ser executados simultaneamente em terminais separados.

**Passo 1: Iniciar a API (Backend)**
Abra o primeiro terminal e execute o servidor FastAPI:
`python -m uvicorn main:app --reload`
A API estará disponível e escutando em `http://127.0.0.1:8000`.

**Passo 2: Iniciar o Dashboard (Frontend)**
Abra um segundo terminal na mesma pasta do projeto e inicie a interface Streamlit:
`streamlit run dashboard.py`

**Passo 3: Utilização**
1. O navegador abrirá automaticamente o painel do Vortex ASPM.
2. Realize o upload de um arquivo `.py` contendo o código a ser auditado.
3. Clique em "Iniciar Varredura" e aguarde a análise dupla e o retorno da IA com as instruções de correção.