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

import os
import time
from datetime import datetime

# PollingObserver: mais compatível com bind mounts do Docker Desktop
# (Windows/Mac) do que o Observer nativo baseado em inotify.
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

from motores.sast import executar_sast
from motores.secrets import executar_secrets
from database import salvar_historico
from ia.gemini import gerar_remediacao_ia
from relatorios import gerar_pdf_seguranca

# Intervalo de checagem do PollingObserver e debounce para evitar reanálises
# duplicadas (editores costumam disparar vários eventos de "modificado" numa
# única gravação: write + flush + metadata, etc.)
POLLING_INTERVALO_SEGUNDOS = 2
DEBOUNCE_SEGUNDOS = 2


class MonitorHandler(FileSystemEventHandler):
    """Dispara SAST + Secrets sempre que o arquivo monitorado é modificado."""

    def __init__(self, caminho_arquivo: str):
        self.caminho_arquivo = caminho_arquivo
        self.ultimo_evento = 0.0

    def on_modified(self, event):
        if event.is_directory or os.path.abspath(event.src_path) != self.caminho_arquivo:
            return

        agora = time.time()
        if agora - self.ultimo_evento < DEBOUNCE_SEGUNDOS:
            return
        self.ultimo_evento = agora

        print(f"🔄 [Monitor] Alteração detectada em {self.caminho_arquivo} às {datetime.now().strftime('%H:%M:%S')}")
        self._reanalisar()

    def _reanalisar(self):
        try:
            resultado_sast = executar_sast(self.caminho_arquivo)

            with open(self.caminho_arquivo, "r", encoding="utf-8") as f:
                codigo = f.read()
            resultado_secrets = executar_secrets(codigo)

            total_falhas = 0
            risco = "BAIXO"
            detalhes_combinados = []

            if resultado_sast.get("status") == "vulneravel":
                total_falhas += resultado_sast.get("total_falhas", 0)
                risco = resultado_sast.get("severidade", risco)
                for falha in resultado_sast.get("detalhes_lista", []):
                    detalhes_combinados.append(f"[SAST] {falha['issue_text']} (Linha: {falha['line_number']})")

            if resultado_secrets.get("status") == "vulneravel":
                total_falhas += resultado_secrets.get("total_falhas", 0)
                risco = "CRÍTICO (Vazamento)"
                falha_sec = resultado_secrets["falha_principal"]
                detalhes_combinados.append(f"[SECRET] Vazamento de {falha_sec['tipo']} (Linha: {falha_sec['linha']})")

            analise_ia = gerar_remediacao_ia("sast", "\n".join(detalhes_combinados)) if detalhes_combinados else None

            nome_relativo = os.path.basename(self.caminho_arquivo)
            salvar_historico(
                nome_relativo,
                total_falhas,
                risco,
                motor="MONITOR",
                analise_ia=analise_ia,
                falha_identificada="\n".join(detalhes_combinados) if detalhes_combinados else None,
            )

            if detalhes_combinados:
                try:
                    gerar_pdf_seguranca({
                        "arquivo_analisado": nome_relativo,
                        "total_falhas": total_falhas,
                        "severidade": risco,
                        "falha_identificada": "\n".join(detalhes_combinados),
                        "analise_ia": analise_ia,
                    })
                except Exception as erro_pdf:
                    print(f"⚠️ [Monitor] Falha ao gerar PDF (reanálise já salva normalmente): {erro_pdf}")

            print(f"✅ [Monitor] Reanálise concluída: {total_falhas} falha(s), risco {risco}")

        except Exception as erro:
            print(f"❌ [Monitor] Erro na reanálise automática: {erro}")


class GerenciadorMonitores:
    """
    Mantém um Observer do watchdog por arquivo monitorado, permitindo
    iniciar/parar individualmente sem afetar outros arquivos monitorados.
    """

    def __init__(self):
        self._observers = {}

    def iniciar(self, caminho_arquivo: str, pasta_observada: str):
        if caminho_arquivo in self._observers:
            return  # já está sendo monitorado, evita duplicar observer

        handler = MonitorHandler(caminho_arquivo)
        observer = Observer(timeout=POLLING_INTERVALO_SEGUNDOS)
        observer.schedule(handler, path=pasta_observada, recursive=False)
        observer.start()
        self._observers[caminho_arquivo] = observer
        print(f"👁️ [Monitor] Observador iniciado para {caminho_arquivo}")

    def parar(self, caminho_arquivo: str):
        observer = self._observers.pop(caminho_arquivo, None)
        if observer:
            observer.stop()
            observer.join(timeout=2)
            print(f"⏹️ [Monitor] Observador parado para {caminho_arquivo}")

    def ativo(self, caminho_arquivo: str) -> bool:
        return caminho_arquivo in self._observers