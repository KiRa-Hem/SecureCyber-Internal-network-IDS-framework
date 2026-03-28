import zipfile
import xml.etree.ElementTree as ET
import sys
import os

def extract_text(docx_path):
    out_path = 'C:/Users/hemes/OneDrive/Desktop/IDS/extracted_report.txt'
    try:
        document = zipfile.ZipFile(docx_path)
        xml_content = document.read('word/document.xml')
        document.close()
        tree = ET.XML(xml_content)
        
        paragraphs = []
        for p in tree.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
            p_text = ''.join(p.itertext())
            if p_text.strip():
                paragraphs.append(p_text.strip())
        
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(paragraphs))
            
        print(f"Successfully wrote {len(paragraphs)} paragraphs to {out_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    extract_text(sys.argv[1])
