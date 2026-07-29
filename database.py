import sqlite3
from datetime import datetime

NOME_BANCO = "banco_aspm.db"

def iniciar_banco():
    """Cria a tabela de histórico se ela não existir."""
    conexao = sqlite3.connect(NOME_BANCO)
    cursor = conexao.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_hora TEXT,
            arquivo TEXT,
            total_falhas INTEGER,
            risco_maximo TEXT
        )
    """)
    conexao.commit()
    conexao.close()

def salvar_historico(arquivo: str, total_falhas: int, risco_maximo: str):
    """Salva um novo registro de varredura no banco de dados."""
    conexao = sqlite3.connect(NOME_BANCO)
    cursor = conexao.cursor()
    data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute(
        "INSERT INTO historico_scans (data_hora, arquivo, total_falhas, risco_maximo) VALUES (?, ?, ?, ?)",
        (data_atual, arquivo, total_falhas, risco_maximo)
    )
    conexao.commit()
    conexao.close()