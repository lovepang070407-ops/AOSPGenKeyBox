#!/usr/bin/env python3

import sys
from pathlib import Path

def prettify_xml(xml_content: str) -> str:
    try:
        import xml.dom.minidom as minidom
        dom = minidom.parseString(xml_content)
        pretty_xml = dom.toprettyxml(indent="    ", encoding=None)
        
        pretty_xml = pretty_xml.replace('</PrivateKey>', '\n</PrivateKey>')
        pretty_xml = pretty_xml.replace('</Certificate>', '\n</Certificate>')
        
        lines = []
        in_pem_block = False
        skip_ec_parameters = False
        parent_indent = 0
        pem_tag_name = ""
        
        for line in pretty_xml.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            
            if stripped == '-----BEGIN EC PARAMETERS-----':
                skip_ec_parameters = True
                continue
            if skip_ec_parameters:
                if stripped == '-----END EC PARAMETERS-----':
                    skip_ec_parameters = False
                continue
            
            if 'format="pem"' in line and stripped.startswith('<') and not stripped.startswith('</'):
                parent_indent = len(line) - len(line.lstrip())
                if '<PrivateKey' in stripped:
                    pem_tag_name = 'PrivateKey'
                elif '<Certificate' in stripped:
                    pem_tag_name = 'Certificate'
                lines.append(line.rstrip())
            
            elif stripped == f'</{pem_tag_name}>' and pem_tag_name:
                lines.append(' ' * parent_indent + stripped)
                pem_tag_name = ""
                parent_indent = 0
            
            elif stripped.startswith('-----BEGIN'):
                in_pem_block = True
                pem_indent = parent_indent + 4
                lines.append(' ' * pem_indent + stripped)
            
            elif stripped.startswith('-----END'):
                pem_indent = parent_indent + 4
                lines.append(' ' * pem_indent + stripped)
                in_pem_block = False
            
            elif in_pem_block:
                pem_indent = parent_indent + 4
                lines.append(' ' * pem_indent + stripped)
            
            else:
                lines.append(line.rstrip())
        
        return '\n'.join(lines)
    except Exception as e:
        raise Exception(f"Failed to prettify XML: {e}")

def prettify_file(input_file: str, output_file: str = None, overwrite: bool = False) -> bool:
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"[ERROR] File '{input_file}' not found")
        return False
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
    except Exception as e:
        print(f"[ERROR] Reading file: {e}")
        return False
    
    try:
        pretty_xml = prettify_xml(xml_content)
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    if overwrite:
        output_path = input_path
    elif output_file:
        output_path = Path(output_file)
    else:
        output_path = input_path.with_stem(input_path.stem + "_pretty")
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)
        print(f"[OK] Prettified XML written to: {output_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Writing file: {e}")
        return False

def prettify_directory(directory: str, pattern: str = "*.xml") -> int:
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"[ERROR] '{directory}' is not a directory")
        return 0
    
    xml_files = list(dir_path.glob(pattern))
    if not xml_files:
        print(f"[WARN] No XML files found in '{directory}'")
        return 0
    
    success_count = 0
    for xml_file in xml_files:
        print(f"[INFO] Processing: {xml_file.name}")
        if prettify_file(str(xml_file)):
            success_count += 1
    return success_count

def main():
    if len(sys.argv) < 2:
        print(f"Usage:\n  {sys.argv[0]} <input.xml> [--overwrite | output.xml]\n  {sys.argv[0]} --dir <directory>")
        sys.exit(1)
    
    if sys.argv[1] == "--dir" and len(sys.argv) >= 3:
        count = prettify_directory(sys.argv[2])
        print(f"Processed {count} file(s) successfully")
        sys.exit(0 if count > 0 else 1)
    
    input_file = sys.argv[1]
    overwrite = "--overwrite" in sys.argv
    output_file = None if overwrite or len(sys.argv) < 3 or sys.argv[2] == "--overwrite" else sys.argv[2]
    
    success = prettify_file(input_file, output_file, overwrite)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
