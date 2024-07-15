import fitz  # PyMuPDF library for PDF processing

def extract_information_from_pdf(pdf_file):
    """
    Extract text information from a PDF file.
    Assumes pdf_file is a Werkzeug FileStorage object.
    """
    # Ensure the PDF file is accessible
    try:
        doc = fitz.open(pdf_file)
        text = ""
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            text += page.get_text()

        return text
    except Exception as e:
        raise RuntimeError(f"Error extracting information from PDF: {str(e)}")
