"""Verify actual persisted files from native-deep-audit.mjs (stdlib only)."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib


def rgba_png(data):
    """Decode our small, non-interlaced 8-bit RGBA fixture, including PNG filters."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    offset, compressed = 8, bytearray()
    while offset < len(data):
        size = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        chunk = data[offset + 8:offset + 8 + size]
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunk)
            assert (depth, color, compression, filtering, interlace) == (8, 6, 0, 0, 0)
            assert width * height <= 4096
        elif kind == b"IDAT":
            compressed.extend(chunk)
        offset += size + 12
    raw = zlib.decompress(compressed)
    stride = width * 4
    assert len(raw) == height * (stride + 1)
    previous, pixels = bytearray(stride), bytearray()
    for row in range(height):
        start = row * (stride + 1)
        mode = raw[start]
        current = bytearray(raw[start + 1:start + 1 + stride])
        assert 0 <= mode <= 4
        for i in range(stride):
            left = current[i - 4] if i >= 4 else 0
            up = previous[i]
            corner = previous[i - 4] if i >= 4 else 0
            if mode == 1:
                predictor = left
            elif mode == 2:
                predictor = up
            elif mode == 3:
                predictor = (left + up) // 2
            elif mode == 4:
                guess = left + up - corner
                distances = [abs(guess - value) for value in (left, up, corner)]
                predictor = (left, up, corner)[distances.index(min(distances))]
            else:
                predictor = 0
            current[i] = (current[i] + predictor) & 255
        pixels.extend(current)
        previous = current
    return width, height, bytes(pixels)


root = Path(sys.argv[1])
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


db = sqlite3.connect(f"file:{root / 'workspace.sqlite3'}?mode=ro", uri=True)
check("SQLite integrity", db.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
check("SQLite foreign keys", not db.execute("PRAGMA foreign_key_check").fetchall())
evidence = db.execute("SELECT id,sha256 FROM evidence").fetchall()
check("Both inert source and ELF persist", len(evidence) == 2)
for ident, digest in evidence:
    check("Archived evidence digest " + ident,
          hashlib.sha256((root / "evidence" / ident).read_bytes()).hexdigest() == digest)
shots = db.execute("SELECT id,sha256,size FROM screenshots").fetchall()
check("One real pasted screenshot persists", len(shots) == 1)
original = (root / "screenshots" / shots[0][0]).read_bytes()
check("Screenshot size and digest", len(original) == shots[0][2]
      and hashlib.sha256(original).hexdigest() == shots[0][1])
with zipfile.ZipFile(root / "audit-report.docx") as archive:
    check("DOCX ZIP integrity", archive.testzip() is None)
    for name in archive.namelist():
        if name.endswith((".xml", ".rels")):
            ET.fromstring(archive.read(name))
    check("DOCX XML parses", True)
    media = [n for n in archive.namelist() if n.startswith("word/media/")]
    check("DOCX contains a real image", len(media) == 1)
    check("DOCX image pixels match original", rgba_png(original) == rgba_png(archive.read(media[0])))
    rels = ET.fromstring(archive.read("word/_rels/document.xml.rels"))
    check("DOCX image has internal relationship", any(
        r.attrib.get("Target") == media[0].removeprefix("word/") and r.attrib.get("TargetMode") != "External" for r in rels))
    text = archive.read("word/document.xml").decode()
    check("DOCX retains recovered title and evidence hash", "[审计] 恢复草稿标题" in text
          and any(digest in text for _, digest in evidence))
html = (root / "audit-report.html").read_text()
encoded = re.search(r"data:image/png;base64,([A-Za-z0-9+/=]+)", html)
check("HTML embeds original screenshot", encoded is not None and base64.b64decode(encoded[1]) == original)
jobs = [json.loads(row[0]) for row in db.execute("SELECT record FROM reverse_jobs")]
check("Cancelled job persists without model call and with confirmed cleanup", len(jobs) == 1
      and jobs[0]["state"] == "cancelled" and jobs[0]["modelRequests"] == 0 and jobs[0]["cleanupConfirmed"])
if len(sys.argv)>3:
    result=json.loads(Path(sys.argv[3]).read_text())
    restored=Path(result['maintenance']['restored']['path'])
    restored_db=sqlite3.connect(f"file:{restored / 'workspace.sqlite3'}?mode=ro",uri=True)
    check("Restored evidence and screenshot rows persist", restored_db.execute('SELECT count(*) FROM evidence').fetchone()[0]==2 and restored_db.execute('SELECT count(*) FROM screenshots').fetchone()[0]==1)
    for ident,digest in evidence:
        check("Restored original hash "+ident,hashlib.sha256((restored/'evidence'/ident).read_bytes()).hexdigest()==digest)
    check("Restored credentials are not presumed available",restored_db.execute("SELECT count(*) FROM settings WHERE key='ai_config'").fetchone()[0]==0)
    restored_db.close()
db.close()
result = {"format": "gaga-deep-artifact-check/1", "checks": checks, "errors": []}
Path(sys.argv[2]).write_text(json.dumps(result, ensure_ascii=False, indent=2))
print(json.dumps({"checks": len(checks), "errors": []}))
