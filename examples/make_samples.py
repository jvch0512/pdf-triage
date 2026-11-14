#!/usr/bin/env python3
"""Writes the hand-made sample PDFs. They are minimal and harmless: no payloads."""
import os
d = os.path.dirname(os.path.abspath(__file__))

def pdf(body, tail=b"%%EOF\n"):
    return b"%PDF-1.4\n" + body + b"trailer\n<< /Root 1 0 R >>\n" + tail

S = {
"clean.pdf": pdf(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"),
"js-openaction.pdf": pdf(b"1 0 obj\n<< /Type /Catalog /OpenAction 3 0 R >>\nendobj\n3 0 obj\n<< /S /JavaScript /JS (app.alert\\('demo'\\);) >>\nendobj\n"),
"launch.pdf": pdf(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AA << /O 4 0 R >> >>\nendobj\n4 0 obj\n<< /S /Launch /F (calc.exe) >>\nendobj\n"),
"obfuscated.pdf": pdf(b"1 0 obj\n<< /Type /Catalog /OpenAction 3 0 R >>\nendobj\n3 0 obj\n<< /S /J#61vaScr#69pt /JS (1) >>\nendobj\n"),
"embedded.pdf": pdf(b"1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 5 0 R >> >>\nendobj\n5 0 obj\n<< /Type /EmbeddedFile /Length 5 >>\nstream\n/JS 1\nendstream\nendobj\n6 0 obj\n<< /S /URI /URI (http://example.test/a) >>\nendobj\n"),
"incremental.pdf": b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n1 0 obj\n<< /Type /Catalog /Encrypt 9 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\nMZ-appended-bytes",
"objstm.pdf": pdf(b"7 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length 3 >>\nstream\nxyz\nendstream\nendobj\n8 0 obj\n<< /Type /Annot /Subtype /RichMedia >>\nendobj\n"),
"fake.pdf": b"This is not a PDF, only named like one.\n",
}
for name, data in S.items():
    open(os.path.join(d, name), "wb").write(data)
