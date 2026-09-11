"""Find file IDs inside a public Google Drive folder."""
import urllib.request, json, re, sys

FOLDER_ID = "19U1VQpspvFOhBwVokKS_wEc3-8_iWcZU"

# Google Drive folder listing via export
url = f"https://drive.google.com/drive/folders/{FOLDER_ID}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

print(f"Fetching folder: {url}")
try:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        html = r.read().decode("utf-8", errors="ignore")
    print(f"Page size: {len(html):,} chars")

    # Extract file IDs and names
    # Pattern: ["filename","file_id","application/...
    patterns = [
        r'"name":"([^"]+)","id":"([^"]+)"',
        r'\["([^"]+\.duckdb)","([A-Za-z0-9_\-]{25,})"\]',
        r'"([A-Za-z0-9_\-]{25,33})"[^}]*"([^"]+\.duckdb)"',
        # Generic file ID pattern in Drive pages
        r'/file/d/([A-Za-z0-9_\-]{25,})/view',
        r'"([A-Za-z0-9_\-]{33})"',  # Drive file IDs are ~33 chars
    ]

    found_ids = set()
    for pat in patterns:
        matches = re.findall(pat, html)
        for m in matches:
            if isinstance(m, tuple):
                print(f"  Match: {m}")
            else:
                if len(m) > 20:
                    found_ids.add(m)

    # Find all file IDs from /file/d/ pattern
    file_ids = re.findall(r'/file/d/([A-Za-z0-9_\-]{25,})', html)
    for fid in set(file_ids):
        print(f"  File ID: {fid}")
        print(f"  Direct URL: https://drive.google.com/uc?export=download&id={fid}")

    # Also try the API approach
    print("\nTrying Drive API (no auth, public folders)...")
    api_url = f"https://www.googleapis.com/drive/v3/files?q=%27{FOLDER_ID}%27+in+parents&key=AIzaSyD-placeholder"
    # This won't work without API key but let's see the error
    
except Exception as e:
    print(f"Error: {e}")
    import traceback; traceback.print_exc()
