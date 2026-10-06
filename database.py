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

import sqlite3
from datetime import datetime

NOME_BANCO = "banco_aspm.db"


def iniciar_banco():
    """Cria a tabela de histórico se ela não existir, e migra bancos antigos sem a coluna 'motor'."""
    conexao = sqlite3.connect(NOME_BANCO, timeout=10)
    cursor = conexao.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_hora TEXT,
            arquivo TEXT,
            total_falhas INTEGER,
            risco_maximo TEXT,
            motor TEXT DEFAULT 'MANUAL',
            analise_ia TEXT,
            falha_identificada TEXT,
            score_risco INTEGER
        )
    """)

    cursor.execute("PRAGMA table_info(historico_scans)")
    colunas_existentes = [linha[1] for linha in cursor.fetchall()]
    if "motor" not in colunas_existentes:
        cursor.execute("ALTER TABLE historico_scans ADD COLUMN motor TEXT DEFAULT 'MANUAL'")
    if "analise_ia" not in colunas_existentes:
        cursor.execute("ALTER TABLE historico_scans ADD COLUMN analise_ia TEXT")
    if "falha_identificada" not in colunas_existentes:
        cursor.execute("ALTER TABLE historico_scans ADD COLUMN falha_identificada TEXT")
    if "score_risco" not in colunas_existentes:
        cursor.execute("ALTER TABLE historico_scans ADD COLUMN score_risco INTEGER")

    cursor.execute("PRAGMA table_info(historico_scans)")
    colunas_finais = [linha[1] for linha in cursor.fetchall()]

    conexao.commit()
    conexao.close()

    print(f"[DB] historico_scans com colunas: {colunas_finais}")


def salvar_historico(
    arquivo: str,
    total_falhas: int,
    risco_maximo: str,
    motor: str = "MANUAL",
    analise_ia: str = None,
    falha_identificada: str = None,
    score_risco: int = None,
):
    """Salva um novo registro de varredura no banco de dados.

    motor: origem do scan, ex. 'SAST', 'SECRETS', 'SCA', 'MONITOR' (monitoramento
    contínuo via watchdog) ou 'CI_CD' (webhook do GitHub).
    analise_ia: texto de remediação gerado pela IA para esse evento.
    falha_identificada: descrição resumida da(s) falha(s) encontrada(s).
    score_risco: score agregado de 0-100 (hoje calculado só pelo motor DAST).
    """
    conexao = sqlite3.connect(NOME_BANCO, timeout=10)
    cursor = conexao.cursor()
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO historico_scans (data_hora, arquivo, total_falhas, risco_maximo, motor, analise_ia, falha_identificada, score_risco) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (data_atual, arquivo, total_falhas, risco_maximo, motor, analise_ia, falha_identificada, score_risco)
    )
    conexao.commit()
    conexao.close()