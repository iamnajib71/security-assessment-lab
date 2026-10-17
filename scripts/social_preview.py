"""Generate a reproducible 1280x640 repository social card from real results."""
import json
from pathlib import Path
from PIL import Image, ImageDraw
from record_demo import font

root = Path(__file__).resolve().parents[1]
data = json.loads((root/'report/findings.json').read_text())
rows = data['findings']; fixed = sum(r['status']=='Fixed - retested' for r in rows)
im = Image.new('RGB',(1280,640),'#0b1b2b'); d=ImageDraw.Draw(im)
d.rectangle((0,0,18,640),fill='#59dfb5')
d.text((74,65),'NAZMUL HASSAN / OWNED HOMELAB',font=font(24),fill='#65e6bd')
d.text((70,140),'Security assessment',font=font(64),fill='#f1f7fc')
d.text((74,228),'Find. Verify. Fix. Retest.',font=font(38),fill='#acbed0')
for x,number,label in [(74,str(len(rows)),'verified findings'),(480,str(fixed),'fixed + retested'),(880,'5','local targets')]:
 d.text((x,340),number,font=font(70),fill='#65e6bd'); d.text((x,430),label,font=font(25),fill='#e3ecf4')
d.text((74,550),'Nmap  /  Nuclei  /  Samba AD  /  Evidence + report',font=font(24),fill='#acbed0')
im.save(root/'docs/social-preview.png')
