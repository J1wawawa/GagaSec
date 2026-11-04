"""Validate physical outputs from the completed isolated native acceptance run."""
import sys, json, sqlite3, hashlib, zipfile, xml.etree.ElementTree as ET
from pathlib import Path
from PIL import Image
from io import BytesIO
native = json.loads(Path(sys.argv[1]).read_text())
root = Path(native['root'])
checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)
db = sqlite3.connect(f'file:{root / "workspace.sqlite3"}?mode=ro', uri=True)
check('Workspace SQLite integrity check', db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok')
check('Workspace has no foreign key violations', not db.execute('PRAGMA foreign_key_check').fetchall())
for file in (root / 'log-index').glob('*.sqlite3'):
    # WAL control files may need to be created after abrupt native client exit.
    idx = sqlite3.connect(f'file:{file}?mode=rw', uri=True)
    check('Log index SQLite integrity: ' + file.name, idx.execute('PRAGMA integrity_check').fetchone()[0] == 'ok')
    idx.close()
shots = db.execute('SELECT id,sha256,size,caption FROM screenshots').fetchall()
for shot_id, digest, size, caption in shots:
    data = (root / 'screenshots' / shot_id).read_bytes()
    check('Restored screenshot bytes still match archived SHA-256', len(data) == size and hashlib.sha256(data).hexdigest() == digest)
with zipfile.ZipFile(root / 'acceptance-with-image.docx') as z:
    check('DOCX ZIP CRC integrity', z.testzip() is None)
    for name in z.namelist():
        if name.endswith('.xml') or name.endswith('.rels'):
            ET.fromstring(z.read(name))
    check('DOCX XML and relationships are well formed', True)
    media = [name for name in z.namelist() if name.startswith('word/media/')]
    check('DOCX embeds both selected original screenshots', len(media) == 2)
    originals = [Image.open(root / 'screenshots' / shot[0]).convert('RGBA') for shot in shots]
    exported = [Image.open(BytesIO(z.read(name))).convert('RGBA') for name in media]
    check('DOCX PNG renderings preserve original dimensions and pixels', all(any(image.size == original.size and image.tobytes() == original.tobytes() for original in originals) for image in exported))
    xml = z.read('word/document.xml').decode()
    check('DOCX contains saved evidence captions and proof', '合成图片' in xml and '本地文件导入' in xml and 'SHA-256' in xml)
html = (root / 'acceptance-with-image.html').read_text()
check('HTML embeds actual PNG data and evidence hash', 'data:image/png;base64,' in html and 'SHA-256' in html)
shared = json.loads((root / 'acceptance-ioc.json').read_text())
stix = json.loads((root / 'acceptance-ioc.stix').read_text())
check('STIX export has actual indicator patterns', stix['type'] == 'bundle' and len(stix['objects']) > 0 and all(i['pattern_type'] == 'stix' for i in stix['objects']))
check('IOC exports omit private analyst notes', '本机合成材料，仅验证标注' not in json.dumps(shared, ensure_ascii=False))
check('CSV export has schema and a selected indicator', (root / 'acceptance-ioc.csv').read_text().startswith('kind,value,verdict,labels') and (root / 'acceptance-ioc.csv').stat().st_size > 40)
raw = db.execute("SELECT value FROM settings WHERE key LIKE 'ai_%'").fetchall()
check('Saved AI configuration has no isolated API key bytes', not any('gaga-isolated-test-key' in v[0] for v in raw))
check('Scheduled assets survived client restart', db.execute("SELECT count(*) FROM monitor_assets WHERE json_extract(record,'$.url') LIKE '%/schedule/%' AND enabled=1").fetchone()[0] == 10)
check('Two actual scheduler rounds survived database reopen', native['schedulerVerification']['snapshots'] >= 20)
db.close()
result = {'format': 'gaga-physical-artifact-check/1', 'root': str(root), 'checks': checks, 'errors': []}
Path(sys.argv[2]).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'checks': len(checks), 'errors': []}))
