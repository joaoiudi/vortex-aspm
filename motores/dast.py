# Vortex ASPM - Application Security Posture Management
# Copyright (C) 2026  João Iudi Oliveira de Souza, Gabriel de Oliveira Gomes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT_SEGUNDOS = 5
MAX_WORKERS = 10

HEADERS_SEGURANCA_ESPERADOS = {
    "Content-Security-Policy": "ALTO",
    "X-Content-Type-Options": "MÉDIO",
    "X-Frame-Options": "MÉDIO",
    "Strict-Transport-Security": "MÉDIO",
    "Referrer-Policy": "BAIXO",
    "Permissions-Policy": "BAIXO",
    "X-XSS-Protection": "BAIXO",
}

HEADERS_PERIGOSOS = {
    "Server": "BAIXO",
    "X-Powered-By": "MÉDIO",
    "X-AspNet-Version": "MÉDIO",
    "X-AspNetMvc-Version": "MÉDIO",
    "X-Generator": "BAIXO",
}

CAMINHOS_SENSIVEIS = [
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.env.backup",
    "/.aws/credentials",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/wp-config.php",
    "/web.config",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/admin",
    "/admin/login",
    "/administrator",
    "/wp-admin",
    "/manager",
    "/panel",
    "/cpanel",
    "/dashboard",
    "/console",
    "/debug",
    "/debug/vars",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/actuator/mappings",
    "/metrics",
    "/health",
    "/__debug__",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/v1/api-docs",
    "/backup.sql",
    "/backup.zip",
    "/dump.sql",
    "/db_backup.sql",
    "/database.sql",
    "/backup.tar.gz",
    "/logs",
    "/error_log",
    "/access.log",
    "/server.log",
    "/phpinfo.php",
    "/test.php",
    "/info.php",
]

PAYLOADS_INJECAO = {
    "XSS Refletido": "<script>alert('vortex_dast')</script>",
    "XSS Refletido (Encoded)": "%3Cscript%3Ealert%28%27vortex_dast%27%29%3C%2Fscript%3E",
    "SQL Injection (Clássico)": "' OR '1'='1",
    "SQL Injection (Comentário)": "' OR 1=1--",
    "SQL Injection (Union)": "' UNION SELECT NULL,NULL,NULL--",
    "SQL Injection (Sleep/Blind)": "'; WAITFOR DELAY '0:0:2'--",
}

ASSINATURAS_ERRO_SQL = [
    "sql syntax",
    "sqlite3.operationalerror",
    "psycopg2",
    "you have an error in your sql",
    "unclosed quotation mark",
    "mysql_fetch",
    "ora-01756",
    "pg::syntaxerror",
    "syntax error at or near",
    "invalid query",
    "sqlstate",
]

PAYLOADS_OPEN_REDIRECT = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https://evil.com%23",
]

PARAMS_REDIRECT = ["next", "url", "redirect", "redirect_to", "return", "returnUrl", "redir", "to", "goto"]

PAYLOADS_TRAVERSAL = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

PARAMS_TRAVERSAL = ["file", "path", "dir", "load", "read", "include", "page", "filename", "doc"]

ASSINATURAS_TRAVERSAL = ["root:x:", "bin:x:", "daemon:x:", "[fonts]", "[extensions]"]

ORDEM_SEVERIDADE = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "MEDIO": 2, "BAIXO": 1}

PONTOS_SEVERIDADE = {"CRÍTICO": 25, "ALTO": 15, "MÉDIO": 8, "MEDIO": 8, "BAIXO": 3}


def calcular_score_risco(achados: list) -> int:
    if not achados:
        return 0
    total_pontos = sum(PONTOS_SEVERIDADE.get(a["issue_severity"], 0) for a in achados)
    bonus_quantidade = min(len(achados) * 2, 20)
    total_pontos += bonus_quantidade
    return min(total_pontos, 100)


def _checar_headers(url_base: str, resposta) -> list:
    achados = []
    for header, severidade in HEADERS_SEGURANCA_ESPERADOS.items():
        if header not in resposta.headers:
            achados.append({
                "issue_text": f"Header de segurança ausente: {header}",
                "issue_severity": severidade,
                "endpoint": url_base,
                "test_id": "DAST-HEADER-MISSING",
            })
    for header, severidade in HEADERS_PERIGOSOS.items():
        if header in resposta.headers:
            achados.append({
                "issue_text": f"Vazamento de tecnologia (Information Disclosure): {header} = {resposta.headers[header]}",
                "issue_severity": severidade,
                "endpoint": url_base,
                "test_id": "DAST-INFO-LEAK",
            })
    return achados


def _checar_cookies(url_base: str, resposta) -> list:
    achados = []
    raw = resposta.headers.get("Set-Cookie", "")
    cookies = [raw] if raw else []
    for cookie in cookies:
        cookie_lower = cookie.lower()
        nome_cookie = cookie.split("=")[0].strip()
        if "httponly" not in cookie_lower:
            achados.append({
                "issue_text": f"Cookie '{nome_cookie}' sem flag 'HttpOnly' (vulnerável a roubo via XSS)",
                "issue_severity": "MÉDIO",
                "endpoint": url_base,
                "test_id": "DAST-COOKIE-HTTPONLY",
            })
        if "secure" not in cookie_lower:
            achados.append({
                "issue_text": f"Cookie '{nome_cookie}' sem flag 'Secure' (pode trafegar em texto claro)",
                "issue_severity": "MÉDIO",
                "endpoint": url_base,
                "test_id": "DAST-COOKIE-SECURE",
            })
        if "samesite" not in cookie_lower:
            achados.append({
                "issue_text": f"Cookie '{nome_cookie}' sem atributo 'SameSite' (risco de CSRF)",
                "issue_severity": "BAIXO",
                "endpoint": url_base,
                "test_id": "DAST-COOKIE-SAMESITE",
            })
    return achados


def _checar_cors(url_base: str) -> list:
    achados = []
    try:
        resp = requests.get(
            url_base,
            headers={"Origin": "https://evil-attacker.com"},
            timeout=TIMEOUT_SEGUNDOS,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acao_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*":
            achados.append({
                "issue_text": "CORS configurado com wildcard '*': qualquer origem pode fazer requisições cross-origin",
                "issue_severity": "MÉDIO",
                "endpoint": url_base,
                "test_id": "DAST-CORS-WILDCARD",
            })
        elif "evil-attacker.com" in acao:
            severity = "CRÍTICO" if acao_creds == "true" else "ALTO"
            achados.append({
                "issue_text": f"CORS reflete origem arbitrária sem validação (ACAO: {acao}, Credentials: {acao_creds})",
                "issue_severity": severity,
                "endpoint": url_base,
                "test_id": "DAST-CORS-REFLECT",
            })
    except requests.RequestException:
        pass
    return achados


def _checar_open_redirect(url_base: str) -> list:
    combinacoes = [(param, payload) for param in PARAMS_REDIRECT for payload in PAYLOADS_OPEN_REDIRECT]

    def testar(combo):
        param, payload = combo
        try:
            resp = requests.get(
                url_base,
                params={param: payload},
                timeout=TIMEOUT_SEGUNDOS,
                allow_redirects=False,
            )
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                return {
                    "issue_text": f"Open Redirect via parâmetro '{param}': redirecionamento para domínio externo não validado",
                    "issue_severity": "MÉDIO",
                    "endpoint": url_base,
                    "test_id": "DAST-OPEN-REDIRECT",
                }
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for future in as_completed([executor.submit(testar, c) for c in combinacoes]):
            resultado = future.result()
            if resultado:
                return [resultado]
    return []


def _checar_directory_traversal(url_base: str) -> list:
    combinacoes = [(param, payload) for param in PARAMS_TRAVERSAL for payload in PAYLOADS_TRAVERSAL]

    def testar(combo):
        param, payload = combo
        try:
            resp = requests.get(url_base, params={param: payload}, timeout=TIMEOUT_SEGUNDOS)
            corpo = resp.text.lower()
            if any(sig in corpo for sig in ASSINATURAS_TRAVERSAL):
                return {
                    "issue_text": f"Directory Traversal via parâmetro '{param}': conteúdo de arquivo do sistema retornado",
                    "issue_severity": "CRÍTICO",
                    "endpoint": url_base,
                    "test_id": "DAST-PATH-TRAVERSAL",
                }
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for future in as_completed([executor.submit(testar, c) for c in combinacoes]):
            resultado = future.result()
            if resultado:
                return [resultado]
    return []


def _checar_rate_limiting(url_base: str) -> list:
    achados = []
    try:
        respostas_ok = 0
        for _ in range(10):
            resp = requests.get(url_base, timeout=TIMEOUT_SEGUNDOS)
            if resp.status_code == 200:
                respostas_ok += 1

        tem_rate_limit = False
        resp_final = requests.get(url_base, timeout=TIMEOUT_SEGUNDOS)
        if resp_final.status_code in (429, 503):
            tem_rate_limit = True
        if resp_final.headers.get("Retry-After") or resp_final.headers.get("X-RateLimit-Limit"):
            tem_rate_limit = True

        if not tem_rate_limit and respostas_ok >= 8:
            achados.append({
                "issue_text": "Rate limiting ausente: 10 requisições consecutivas aceitas sem bloqueio (risco de força bruta e DDoS)",
                "issue_severity": "MÉDIO",
                "endpoint": url_base,
                "test_id": "DAST-RATE-LIMIT",
            })
    except requests.RequestException:
        pass
    return achados


def _checar_endpoints_expostos(url_base: str) -> list:
    achados = []
    base = url_base.rstrip("/")

    def verificar_caminho(caminho):
        try:
            resp = requests.get(base + caminho, timeout=TIMEOUT_SEGUNDOS, allow_redirects=False)
            if resp.status_code == 200:
                if any(k in caminho for k in [".env", "credentials", ".git", "config", "backup", ".sql", ".tar"]):
                    sev = "CRÍTICO"
                elif any(k in caminho for k in ["admin", "wp-admin", "phpinfo", "actuator"]):
                    sev = "ALTO"
                else:
                    sev = "MÉDIO"
                return {
                    "issue_text": f"Endpoint/arquivo sensível acessível publicamente: {caminho}",
                    "issue_severity": sev,
                    "endpoint": base + caminho,
                    "test_id": "DAST-EXPOSURE",
                }
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(verificar_caminho, c): c for c in CAMINHOS_SENSIVEIS}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                achados.append(resultado)
    return achados


def _checar_injecao_refletida(url_base: str) -> list:
    achados = []

    def testar_payload(nome_ataque, payload):
        resultados_locais = []
        try:
            resp = requests.get(
                url_base,
                params={"q": payload, "search": payload, "id": payload, "input": payload},
                timeout=TIMEOUT_SEGUNDOS,
            )
            corpo = resp.text
            if nome_ataque.startswith("XSS") and payload in corpo:
                resultados_locais.append({
                    "issue_text": f"Possível {nome_ataque}: payload refletido sem sanitização",
                    "issue_severity": "CRÍTICO",
                    "endpoint": url_base,
                    "test_id": "DAST-XSS",
                })
            elif "SQL" in nome_ataque:
                if payload in corpo:
                    resultados_locais.append({
                        "issue_text": f"Possível {nome_ataque}: payload refletido na resposta",
                        "issue_severity": "CRÍTICO",
                        "endpoint": url_base,
                        "test_id": "DAST-SQLI",
                    })
                elif any(sig in corpo.lower() for sig in ASSINATURAS_ERRO_SQL):
                    resultados_locais.append({
                        "issue_text": f"Possível {nome_ataque}: mensagem de erro de BD exposta",
                        "issue_severity": "CRÍTICO",
                        "endpoint": url_base,
                        "test_id": "DAST-SQLI-ERROR",
                    })
        except requests.RequestException:
            pass
        return resultados_locais

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(testar_payload, nome, payload) for nome, payload in PAYLOADS_INJECAO.items()]
        for future in as_completed(futures):
            achados.extend(future.result())

    vistos = set()
    deduplicados = []
    for a in achados:
        if a["test_id"] not in vistos:
            vistos.add(a["test_id"])
            deduplicados.append(a)
    return deduplicados


def executar_dast(url_alvo: str) -> dict:
    if not url_alvo.startswith("http"):
        url_alvo = "http://" + url_alvo

    try:
        resposta_inicial = requests.get(url_alvo, timeout=TIMEOUT_SEGUNDOS)
    except requests.RequestException as erro:
        return {"status": "erro", "mensagem": f"Não foi possível conectar ao alvo '{url_alvo}': {erro}"}

    achados = []
    achados += _checar_headers(url_alvo, resposta_inicial)
    achados += _checar_cookies(url_alvo, resposta_inicial)

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(_checar_endpoints_expostos, url_alvo): "endpoints",
            executor.submit(_checar_injecao_refletida, url_alvo): "injecao",
            executor.submit(_checar_cors, url_alvo): "cors",
            executor.submit(_checar_open_redirect, url_alvo): "redirect",
            executor.submit(_checar_directory_traversal, url_alvo): "traversal",
            executor.submit(_checar_rate_limiting, url_alvo): "ratelimit",
        }
        for future in as_completed(futures):
            try:
                achados += future.result()
            except Exception:
                pass

    if not achados:
        return {
            "status": "sucesso",
            "mensagem": "✅ Nenhuma vulnerabilidade dinâmica encontrada!",
            "score_risco": 0,
        }

    severidade_maxima = max(achados, key=lambda a: ORDEM_SEVERIDADE.get(a["issue_severity"], 0))["issue_severity"]
    score = calcular_score_risco(achados)
    achados_ordenados = sorted(achados, key=lambda a: ORDEM_SEVERIDADE.get(a["issue_severity"], 0), reverse=True)

    return {
        "status": "vulneravel",
        "total_falhas": len(achados),
        "severidade_maxima": severidade_maxima,
        "score_risco": score,
        "detalhes_lista": achados_ordenados,
    }