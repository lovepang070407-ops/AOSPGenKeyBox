#!/usr/bin/env python3
"""
XML Prettifier for Android Keybox
Formats XML with 4-space indentation and proper PEM block formatting
"""

import os
import sys
from pathlib import Path


def prettify_xml(xml_content: str) -> str:
	"""
	Prettify XML with 4-space indentation matching Android keybox format
	PEM blocks get +4 space indentation relative to their opening tag
	Closing tags maintain same indent as opening tags
	"""
	try:
		import xml.dom.minidom as minidom
		dom = minidom.parseString(xml_content)
		
		# Use 4-space indent to match Android format
		pretty_xml = dom.toprettyxml(indent="    ", encoding=None)
		
		# Process lines to add proper PEM block indentation
		lines = []
		in_pem_block = False
		parent_indent = 0
		pem_tag_name = ""
		
		for line in pretty_xml.split('\n'):
			stripped = line.strip()
			
			# Skip completely empty lines
			if not stripped:
				continue
			
			# Detect start of PEM format tags (PrivateKey or Certificate with format="pem")
			if 'format="pem"' in line and stripped.startswith('<') and not stripped.startswith('</'):
				# This is the opening tag - remember its indentation
				parent_indent = len(line) - len(line.lstrip())
				# Extract tag name for closing tag matching
				if '<PrivateKey' in stripped:
					pem_tag_name = 'PrivateKey'
				elif '<Certificate' in stripped:
					pem_tag_name = 'Certificate'
				lines.append(line.rstrip())
			
			# Detect closing tags for PEM containers
			elif stripped == f'</{pem_tag_name}>' and pem_tag_name:
				# Closing tag should have same indent as opening tag
				lines.append(' ' * parent_indent + stripped)
				pem_tag_name = ""
				parent_indent = 0
			
			# Detect PEM block start
			elif stripped.startswith('-----BEGIN'):
				in_pem_block = True
				# PEM content should be parent indent + 4 spaces
				pem_indent = parent_indent + 4
				lines.append(' ' * pem_indent + stripped)
			
			# Detect PEM block end
			elif stripped.startswith('-----END'):
				# Same indentation as BEGIN
				pem_indent = parent_indent + 4
				lines.append(' ' * pem_indent + stripped)
				in_pem_block = False
			
			# Inside PEM block (certificate/key data)
			elif in_pem_block:
				# Same indentation as BEGIN/END
				pem_indent = parent_indent + 4
				lines.append(' ' * pem_indent + stripped)
			
			# Regular XML lines
			else:
				lines.append(line.rstrip())
		
		return '\n'.join(lines)
		
	except Exception as e:
		raise Exception(f"Failed to prettify XML: {e}")


def prettify_file(input_file: str, output_file: str = None, overwrite: bool = False) -> bool:
	"""
	Prettify an XML file
	
	Args:
		input_file: Path to input XML file
		output_file: Path to output file (optional)
		overwrite: If True, overwrites the input file
	
	Returns:
		True if successful, False otherwise
	"""
	input_path = Path(input_file)
	
	if not input_path.exists():
		print(f"[ERROR] File '{input_file}' not found")
		return False
	
	# Read the XML content
	try:
		with open(input_path, 'r', encoding='utf-8') as f:
			xml_content = f.read()
	except Exception as e:
		print(f"[ERROR] Reading file: {e}")
		return False
	
	# Prettify the XML
	try:
		pretty_xml = prettify_xml(xml_content)
	except Exception as e:
		print(f"[ERROR] {e}")
		return False
	
	# Determine output file
	if overwrite:
		output_path = input_path
	elif output_file:
		output_path = Path(output_file)
	else:
		# Default: add _pretty suffix
		output_path = input_path.with_stem(input_path.stem + "_pretty")
	
	# Write the prettified XML
	try:
		with open(output_path, 'w', encoding='utf-8') as f:
			f.write(pretty_xml)
		print(f"[OK] Prettified XML written to: {output_path}")
		return True
	except Exception as e:
		print(f"[ERROR] Writing file: {e}")
		return False


def prettify_directory(directory: str, pattern: str = "*.xml") -> int:
	"""
	Prettify all XML files in a directory
	
	Args:
		directory: Path to directory
		pattern: File pattern to match (default: *.xml)
	
	Returns:
		Number of files successfully processed
	"""
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
	"""Main entry point for command-line usage"""
	if len(sys.argv) < 2:
		print("XML Prettifier for Android Keybox v1.3")
		print("=" * 60)
		print("\nUsage:")
		print(f"  {sys.argv[0]} <input.xml> [output.xml]")
		print(f"  {sys.argv[0]} <input.xml> --overwrite")
		print(f"  {sys.argv[0]} --dir <directory>")
		print("\nExamples:")
		print(f"  {sys.argv[0]} keybox.xml")
		print(f"  {sys.argv[0]} keybox.xml keybox_formatted.xml")
		print(f"  {sys.argv[0]} keybox.xml --overwrite")
		print(f"  {sys.argv[0]} --dir 20251201-062827-UTC")
		print("\nFeatures:")
		print("  - 4-space indentation for XML elements")
		print("  - +4 space indentation for PEM blocks relative to parent")
		print("  - Proper closing tag alignment")
		print("  - Matches official Android Keybox format")
		sys.exit(1)
	
	# Directory mode
	if sys.argv[1] == "--dir" and len(sys.argv) >= 3:
		count = prettify_directory(sys.argv[2])
		print(f"\n{'='*60}")
		print(f"Processed {count} file(s) successfully")
		sys.exit(0 if count > 0 else 1)
	
	# File mode
	input_file = sys.argv[1]
	overwrite = "--overwrite" in sys.argv
	output_file = None if overwrite or len(sys.argv) < 3 or sys.argv[2] == "--overwrite" else sys.argv[2]
	
	success = prettify_file(input_file, output_file, overwrite)
	sys.exit(0 if success else 1)


if __name__ == "__main__":
	main()
