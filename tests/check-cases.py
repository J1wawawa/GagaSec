"""Independent physical verification of complete cases, raw archives and exported documents."""
import sys, json, sqlite3, hashlib, zipfile, base64, html, re
from pathlib import Path
from io import BytesIO
from PIL import Image
from xml.etree import ElementTree as ET
result=json.loads(Path(sys.argv[1]).read_text())
root=Path(result['root'])
manifest=json.loads((root/'case-materials/manifest.json').read_text())
# WAL readers may need to create shared-memory sidecars after all native connections close.
db=sqlite3.connect(root/'workspace.sqlite3')
db.execute('PRAGMA query_only=ON')
db.row_factory=sqlite3.Row
checks=[]
def check(label,value):
    if not value: raise AssertionError(label)
    checks.append(label)
check('SQLite integrity',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok')
check('SQLite references',not db.execute('PRAGMA foreign_key_check').fetchall())
for name,f in manifest['files'].items():
    raw=(root/'case-materials'/name).read_bytes()
    check('Fixture hash '+name,len(raw)==f['size'] and hashlib.sha256(raw).hexdigest()==f['sha256'])
for s in manifest['scenarios']:
    case=db.execute('SELECT * FROM cases WHERE title=?',(s['title'],)).fetchone();cid=case['id']
    evidence=db.execute('SELECT * FROM evidence WHERE case_id=?',(cid,)).fetchall()
    nodes=db.execute('SELECT * FROM nodes WHERE case_id=? ORDER BY occurred_at,recorded_at',(cid,)).fetchall()
    check(s['id']+' independent evidence count',len(evidence)==len(s['materials']))
    for e in evidence:
        raw=(root/'evidence'/e['id']).read_bytes()
        check(s['id']+' raw archive integrity '+e['kind'],len(raw)==e['size'] and hashlib.sha256(raw).hexdigest()==e['sha256'])
        m=next(m for m in s['materials'] if m['kind']==e['kind'])
        if e['kind'] not in ('http','triage'): check(s['id']+' original matches fixture '+e['kind'],raw==(root/'case-materials'/m['file']).read_bytes())
    draft=json.loads(db.execute('SELECT value FROM settings WHERE key=?',('report_draft:'+cid,)).fetchone()[0])
    check(s['id']+' saved report independent',draft['title']==s['reportTitle'] and next((step.get('body',draft.get('conclusion','')) for step in draft['steps'] if step['id']=='outcome'),'')==s['conclusion'])
    check(s['id']+' event metadata persisted',all(draft[k]==v for k,v in s['reportMetadata'].items() if k!='discoveredAt'))
    check(s['id']+' five-step owners, status and chapter content persisted',len(draft['steps'])==5 and all(a['id']==b['id'] and a['owner']==b['owner'] and a['status']==b['status'] and a.get('body',draft.get(b['key'],''))==b['body'] for a,b in zip(draft['steps'],s['reportSteps'])))
    check(s['id']+' linked proof nodes belong only to their case',all(any(n['id']==nid for n in nodes) for step in draft['steps'] for nid in step['nodeIds']))
    selected=[n for n in nodes if n['included']]
    check(s['id']+' chronological source order',all(a['occurred_at']<=b['occurred_at'] for a,b in zip(selected,selected[1:])))
    shots=db.execute('SELECT s.* FROM screenshots s JOIN nodes n ON s.node_id=n.id WHERE n.case_id=?',(cid,)).fetchall()
    originals=[]
    for shot in shots:
        raw=(root/'screenshots'/shot['id']).read_bytes()
        check(s['id']+' screenshot integrity',len(raw)==shot['size'] and hashlib.sha256(raw).hexdigest()==shot['sha256'])
        originals.append(Image.open(BytesIO(raw)).convert('RGBA'))
    with zipfile.ZipFile(root/(s['id']+'-report.docx')) as z:
        check(s['id']+' DOCX ZIP integrity',z.testzip() is None)
        for name in z.namelist():
            if name.endswith(('.xml','.rels')): ET.fromstring(z.read(name))
        doc=ET.fromstring(z.read('word/document.xml'))
        text=''.join(doc.itertext())
        check(s['id']+' DOCX report sections and node bodies',all(draft[f] in text for f in ['title','author','summary','scope','conclusion','recommendations']) and all(n['title'] in text for n in selected) and '[案例验收复核]' in text)
        check(s['id']+' DOCX five chapters and responsible people present',all(step['owner'] in text and step['body'] in text for step in s['reportSteps']) and all(v in text for k,v in s['reportMetadata'].items() if k!='discoveredAt'))
        check(s['id']+' DOCX evidence hashes preserved',all(e['sha256'] in text for e in evidence if any(n['evidence_id']==e['id'] for n in selected)))
        media=[name for name in z.namelist() if name.startswith('word/media/')]
        exported=[Image.open(BytesIO(z.read(name))).convert('RGBA') for name in media]
        check(s['id']+' DOCX screenshot pixels preserved',len(exported)==len(originals)>0 and all(any(a.size==b.size and a.tobytes()==b.tobytes() for b in originals) for a in exported))
        check(s['id']+' DOCX labels synthetic figure and missing pictures','不是现场截图' in text and '截图预留' in text)
    exported=(root/(s['id']+'-report.html')).read_text()
    plain=html.unescape(re.sub('<[^>]+>','',exported))
    check(s['id']+' HTML report sections and nodes',all(draft[f] in plain for f in ['title','summary','scope','conclusion','recommendations']) and all(n['title'] in plain for n in selected))
    check(s['id']+' HTML five chapters and responsible people present',all(step['owner'] in plain and step['body'] in plain for step in s['reportSteps']) and all(v in plain for k,v in s['reportMetadata'].items() if k!='discoveredAt'))
    images=re.findall('data:image/png;base64,([^\'\"]+)',exported)
    check(s['id']+' HTML embeds archived PNG bytes',len(images)==len(shots)>0 and {hashlib.sha256(base64.b64decode(i)).hexdigest() for i in images}=={s['sha256'] for s in shots})
    for other in manifest['scenarios']:
        if other['id']!=s['id']:check(s['id']+' report excludes '+other['id'],other['reportTitle'] not in plain and other['summary'] not in plain)
    stix=json.loads((root/(s['id']+'-ioc.stix')).read_text())
    check(s['id']+' STIX contains only selected case indicator',stix['type']=='bundle' and len(stix['objects'])>0 and all(s['indicator'] in obj['pattern'] for obj in stix['objects']))
    csv=(root/(s['id']+'-ioc.csv')).read_text()
    check(s['id']+' CSV portable indicator present',csv.startswith('kind,value,verdict,labels') and s['indicator'] in csv)
    reviews=db.execute('SELECT r.record FROM ai_reviews r JOIN evidence e ON r.evidence_id=e.id WHERE e.case_id=?',(cid,)).fetchall()
    for row in reviews:
        r=json.loads(row[0]);check(s['id']+' official AI record with raw result and valid citations',r['endpoint']=='https://api.deepseek.com' and r['content'] and r['assessment'] and any(a['refs'] for a in r['assessment']['reasons']) and r['assessment']['attackSuccess']!='confirmed')
    check(s['id']+' node edits retain audit history',db.execute('SELECT count(*) FROM node_revisions r JOIN nodes n ON r.node_id=n.id WHERE n.case_id=?',(cid,)).fetchone()[0]>=1)
    index=root/'log-index'/(cid+'.sqlite3')
    idx=sqlite3.connect(index)
    check(s['id']+' derived index integrity',idx.execute('PRAGMA integrity_check').fetchone()[0]=='ok')
    if s['id']=='B-ssh':check('SSH tail exact source time preserved',any(n['occurred_at']=='2026-10-27T08:50:12+08:00' and '原文第 3002 行' in n['body'] for n in nodes))
    if s['id']=='D-gaps':check('Unknown-time original stays unnormalized',idx.execute('SELECT count(*) FROM events WHERE at IS NULL').fetchone()[0]==1)
    idx.close()
check('AI records match the mode actually tested',db.execute('SELECT count(*) FROM ai_reviews').fetchone()[0]==(0 if result.get('localOnly') else 9) and db.execute('SELECT count(*) FROM ai_followups').fetchone()[0]==(0 if result.get('localOnly') else 1))
if not result.get('localOnly'): check('False-positive control has saved human feedback',db.execute("SELECT count(*) FROM review_feedback WHERE json_extract(record,'$.disposition')='false_positive'").fetchone()[0]==1)
db.close()
out={'format':'gaga-complete-case-artifacts/1','root':str(root),'checks':checks,'errors':[]}
Path(sys.argv[2]).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'errors':[]}))
