import urllib.request, re, json

FOLDER_ID = "19U1VQpspvFOhBwVokKS_wEc3-8_iWcZU"
url = f"https://drive.google.com/drive/folders/{FOLDER_ID}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

req = urllib.request.Request(url, headers=headers)
with urllib.request.urlopen(req, timeout=20) as r:
    html = r.read().decode("utf-8", errors="ignore")

# Find all 33-char Drive file IDs (standard format)
ids = re.findall(r'["\s]([A-Za-z0-9_\-]{33})["\s/]', html)
unique_ids = list(dict.fromkeys(ids))  # preserve order, deduplicate
print(f"Candidate file IDs found: {len(unique_ids)}")
for fid in unique_ids[:30]:
    print(f"  {fid}  →  https://drive.google.com/uc?export=download&id={fid}&confirm=t")

# Also look for .duckdb filename mentions
duckdb_ctx = [(m.start(), html[max(0,m.start()-200):m.end()+200]) 
              for m in re.finditer(r'duckdb', html, re.IGNORECASE)]
print(f"\n.duckdb mentions: {len(duckdb_ctx)}")
for pos, ctx in duckdb_ctx[:3]:
    # Extract ID near the mention
    nearby_ids = re.findall(r'[A-Za-z0-9_\-]{33}', ctx)
    print(f"  Context IDs near 'duckdb': {nearby_ids}")
    print(f"  Snippet: {ctx[100:250].replace(chr(10),' ')[:200]}")
