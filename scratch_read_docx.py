import zipfile
import xml.etree.ElementTree as ET
import sys

def extract_text_from_docx(docx_path):
    try:
        with zipfile.ZipFile(docx_path) as z:
            xml_content = z.read('word/document.xml')
            tree = ET.fromstring(xml_content)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            
            # Extract text from paragraphs to preserve some structure
            paragraphs = []
            for p in tree.findall('.//w:p', ns):
                texts = [node.text for node in p.findall('.//w:t', ns) if node.text]
                if texts:
                    paragraphs.append(''.join(texts))
            
            return '\n'.join(paragraphs)
    except Exception as e:
        return f"Error reading docx: {e}"

if __name__ == "__main__":
    path = r'c:\Cognitiveinsight\CodeFolder\core\docs\governance-planes-agentic-ai.docx'
    with open(r'c:\Cognitiveinsight\CodeFolder\docx_content.txt', 'w', encoding='utf-8') as f:
        f.write(extract_text_from_docx(path))
