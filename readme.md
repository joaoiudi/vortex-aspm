# Vortex ASPM (Application Security Posture Management)

Plataforma corporativa de **Gestão de Postura de Segurança de Aplicações (ASPM)** com multimotores de análise e inteligência artificial generativa (Google Gemini) integrada para remediação automatizada de vulnerabilidades.

---

## Arquitetura e Tecnologias

| Camada | Tecnologia | Descrição |
|---|---|---|
| **Backend API** | [FastAPI](https://fastapi.tiangolo.com/) | API REST assíncrona de orquestração de scans e ingestão de métricas |
| **Frontend / SOC** | [Streamlit](https://streamlit.io/) | Dashboard reativo padrão Security Operations Center |
| **Persistência** | [SQLite](https://www.sqlite.org/) | Histórico de postura, falhas e eventos de segurança |
| **Inteligência Artificial** | [Google Gemini](https://ai.google.dev/) | Remediação e geração automatizada de código seguro |
| **Monitoramento Contínuo** | [Watchdog](https://pypi.org/project/watchdog/) | Monitoramento em tempo real do sistema de arquivos |
| **Orquestração** | [Docker](https://www.docker.com/) & Docker Compose | Contêineres isolados para backend e frontend |

---

## Motores de Segurança Implementados

A plataforma avalia a superfície de ataque em múltiplas camadas fundamentais:

* **SAST (Static Application Security Testing):** Analisa o código-fonte em busca de falhas lógicas e estruturais (SQL Injection, Command Injection, uso inseguro de `eval()`, criptografia fraca como MD5 e Path Traversal).
* **Secrets Detection:** Realiza varreduras baseadas em expressões regulares avançadas para identificar vazamento de credenciais hardcoded (AWS Access Keys, tokens JWT, chaves de API, senhas).
* **SCA (Software Composition Analysis):** Inspeciona dependências e bibliotecas de terceiros contra bancos de vulnerabilidades conhecidas (CVEs) via `pip-audit`.
* **Micro-DAST (Dynamic Application Security Testing):** Intercepta o tráfego de aplicações ativas via HTTP, identificando ausência de cabeçalhos de segurança (CSP, HSTS), flags inseguras de cookies (`HttpOnly`, `Secure`) e vazamento de stack tecnológica.
* **Remediação via IA (Gemini):** Gera tickets de incidentes estruturados e código corrigido pronto para aplicação.

---

## Configuração do Ambiente

### 1. Clonar o Repositório
```bash
git clone https://github.com/joaoiudi/vortex-aspm.git
cd vortex-aspm
```

### 2. Configurar o Arquivo `.env`
Copie o modelo de ambiente `.env.example` para `.env` e preencha com a sua chave da API:

```bash
cp .env.example .env
```

Edite o arquivo `.env`:
```env
GEMINI_API_KEY=sua_chave_aqui
GEMINI_MODEL=gemini-3.5-flash-lite
```

### 3. (Opcional) Conferir Modelos Liberados para sua Chave
Após configurar o `.env`, você pode rodar o script utilitário [`listar_modelos.py`](file:///e:/VORTEXaspm/listar_modelos.py). Ele consulta a API do Google GenAI com a chave configurada e lista todos os modelos disponíveis na sua cota:

```bash
python listar_modelos.py
```
> Caso prefira usar outro modelo listado (como `gemini-3.5-flash-lite` ou `gemini-2.5-flash`), basta ajustar o valor de `GEMINI_MODEL` no `.env`.

---

## Como Executar o Projeto

### Opção 1: Via Docker Compose (Recomendado)

Construa as imagens e suba todos os serviços em segundo plano:
```bash
docker-compose up --build -d
```

Acesse no navegador:
* **Dashboard (SOC / Interface Visual):** [http://localhost:8501](http://localhost:8501) ou [http://127.0.0.1:8501](http://127.0.0.1:8501)
* **API (Documentação Swagger FastAPI):** [http://localhost:8000/docs](http://localhost:8000/docs) ou [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) 

Para parar os serviços:
```bash
docker-compose down
```

---

### Opção 2: Execução Local (Sem Docker)

1. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Inicie o Backend (FastAPI):**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Inicie o Frontend (Streamlit):**
   Em outro terminal:
   ```bash
   streamlit run dashboard.py
   ```

---

## Guia Prático de Uso da Plataforma

Após iniciar a aplicação e acessar o Dashboard em **[http://localhost:8501](http://localhost:8501)**, você terá à disposição 3 abas operacionais padrão SOC:

---

### 1. Análise de Código: Varredura Única (SAST + Secrets)
Identifica falhas estruturais de programação (SQL Injection, Command Injection, RCE via `eval()`, Path Traversal, Pickle inseguro, MD5 fraco) e credenciais hardcoded (chaves AWS, JWT, senhas expostas).

1. Acesse a aba **` Código (SAST/Secrets)`**.
2. Clique no campo de upload e envie um arquivo Python (`.py`).
   >  **Dica de teste:** Você pode criar um arquivo Python de teste (ex: `teste_vulneravel.py`) contendo falhas propositais (como `eval()`, queries SQL concatenadas ou credenciais expostas) para avaliar a resposta dos motores.
3. Clique no botão **` Executar Varredura Única`**.
4. O painel exibirá o progresso em tempo real enquanto a IA analisa o código e sintetiza as correções.
5. Ao concluir, você verá:
   * **Cartões de Métricas:** Total de falhas, risco máximo e arquivo analisado.
   * **Lista de Alertas:** Cada falha mapeada com seu tipo e número de linha.
   * **Remediação Sugerida pela IA:** Ticket técnico corporativo contendo o código seguro pronto para substituição.
   * **Botão de Download:** Baixe o relatório executivo completo em formato PDF.

---

### 2. Monitoramento Contínuo em Tempo Real (Watchdog)
Modo autônomo onde o Vortex vigia alterações no código em segundo plano e executa a reanálise automaticamente toda vez que o arquivo for salvo.

1. Na aba **` Código (SAST/Secrets)`**, faça o upload do arquivo que deseja vigiar.
   > ⚠️ **Requisito:** O arquivo a ser monitorado **deve estar localizado dentro da pasta `workspace/`** do projeto. O motor de monitoramento contínuo observa exclusivamente esse diretório. Arquivos fora dele não serão detectados.
2. Clique no botão **` Ativar Monitoramento Contínuo`**.
3. O status mudará para verde: ` Monitoramento Contínuo Ativo`.
4. Abra o arquivo no seu editor de código (ex: VS Code) e faça uma modificação ou corrija uma falha.
5. Ao salvar o arquivo (`Ctrl + S`), o guardião do Vortex detecta o evento do sistema operacional, executa os motores de segurança e atualiza o histórico do dashboard automaticamente, sem necessidade de cliques manuais.
6. Para encerrar a vigilância, clique em **` Parar Monitoramento`**.

---

### 3. Auditoria de Dependências (SCA)
Cruza as bibliotecas declaradas no projeto contra bancos globais de vulnerabilidades conhecidas (CVEs / OSV) via `pip-audit`.

1. Acesse a aba **` Dependências (SCA)`**.
2. Faça o upload do arquivo `requirements.txt` da aplicação.
   > **Exemplo de teste vulnerável:** Um arquivo contendo dependências desatualizadas:
   > ```text
   > flask==0.12
   > requests==2.6.0
   > ```
3. Clique em **` Executar Varredura SCA`**.
4. Acompanhe a esteira de auditoria. O Vortex listará as CVEs identificadas, versões afetadas e a IA gerará as instruções de atualização e mitigações recomendadas.

---

### 4. Varredura Dinâmica em Tempo de Execução (DAST)
Avalia a segurança da aplicação ativa sob a perspectiva de um atacante externo via requisições HTTP reais.

1. Acesse a aba **` Dinâmico (DAST)`**.
2. No campo **URL do alvo**, informe o endereço da aplicação em execução:
   * **Execução via Docker:** `http://backend:8000` (testa a própria API do Vortex pela rede interna).
   * **Execução local:** `http://localhost:8000` (ou qualquer serviço web HTTP que você deseje auditar).
3. Clique em **` Executar Varredura DAST`**.
4. O motor inspecionará ausência de cabeçalhos de segurança (CSP, HSTS, X-Content-Type-Options), flags inseguras em cookies (`HttpOnly`, `Secure`) e vazamento de versão.
5. O painel calculará o **Score de Risco Agregado (0 a 100)** e exibirá as diretrizes de hardening geradas pela IA.

---

### 5. Gestão de Postura e Histórico Global
No rodapé do dashboard, a seção **Gestão de Postura** consolida todos os scans realizados:
* **Gráfico de Evolução:** Visualização temporal do total de vulnerabilidades ao longo dos scans.
* **Distribuição de Origem:** Gráfico comparativo entre varreduras Manuais, Monitoramento Contínuo, SCA e DAST.
* **Tabela de Auditoria:** Histórico completo de eventos para conformidade e rastreabilidade.

## Equipe de Desenvolvimento

Projeto desenvolvido para o challenge da **PRIDE Security** para o curso de **Defesa Cibernética**:

* **João Iudi Oliveira de Souza**
* **Gabriel de Oliveira Gomes**

## Licença
Este projeto é licenciado sob a GNU General Public License v3.0. Veja o arquivo [LICENSE.md](LICENSE.md).