from fpdf import FPDF
from datetime import datetime

class PDFRelatorio(FPDF):
    def header(self):
        # Cabeçalho do Relatório
        self.set_font("helvetica", "B", 16)
        self.set_text_color(30, 41, 59)
        self.cell(0, 10, "Vortex ASPM - Relatorio de Seguranca", 0, 1, "L")
        
        self.set_font("helvetica", "", 10)
        self.set_text_color(100, 116, 139)
        self.cell(0, 5, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", 0, 1, "L")
        self.ln(5)
        
        # Linha divisoria
        self.set_draw_color(203, 213, 225)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(10)

    def footer(self):
        # Rodapé com número da página
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Pagina {self.page_no()}", 0, 0, "C")

def gerar_pdf_seguranca(dados_scan: dict) -> str:
    """Cria um arquivo PDF com os resultados da varredura e retorna o caminho do arquivo."""
    pdf = PDFRelatorio()
    pdf.add_page()
    
    # Bloco de Métricas / Resumo
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "Resumo Executivo da Analise", 0, 1)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 6, f"Arquivo Analisado: {dados_scan.get('arquivo_analisado', 'alvo_teste.py')}", 0, 1)
    pdf.cell(0, 6, f"Total de Falhas Encontradas: {dados_scan.get('total_falhas', 0)}", 0, 1)
    pdf.cell(0, 6, f"Risco Maximo: {dados_scan.get('severidade', 'N/A')}", 0, 1)
    pdf.ln(5)
    
    # Detalhe das Falhas
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 8, "Falhas Identificadas", 0, 1)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(185, 28, 28) # Vermelho alerta
    # Usando multi_cell para quebrar texto longo automaticamente
    pdf.multi_cell(0, 6, f"{dados_scan.get('falha_identificada', 'Nenhuma falha')}")
    pdf.set_text_color(15, 23, 42)
    pdf.ln(5)
    
    # Remediação da IA
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 8, "Plano de Remediacao Sugerido (IA)", 0, 1)
    
    pdf.set_font("helvetica", "", 9)
    # Limpa caracteres especiais que o FPDF padrão não suporta
    texto_ia = dados_scan.get('analise_ia', 'Sem analise').encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 5, texto_ia)
    
    # Salva o arquivo no disco
    nome_arquivo_pdf = "relatorio_seguranca.pdf"
    pdf.output(nome_arquivo_pdf)
    
    return nome_arquivo_pdf