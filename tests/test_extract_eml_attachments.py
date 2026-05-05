from pathlib import Path

from phishing.extract_eml_attachments import safe_filename


def test_safe_filename_removes_path_separators():
    assert safe_filename('../evil/file.txt') == '.._evil_file.txt'


def test_safe_filename_empty():
    assert safe_filename('') == 'attachment.bin'
