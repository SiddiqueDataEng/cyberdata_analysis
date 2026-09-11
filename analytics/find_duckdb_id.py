"""Check which Google Drive file ID is the duckdb warehouse (by checking file info)."""
import urllib.request, re

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# All candidate IDs from the folder
IDS = [
    "1c1T84Z1Vy5xDKLxw6V6IassbsXYyPU1I",
    "1He3k_3i1SviYFZRnh17Py-K9Dwd0Wjf0",
    "11pO5jmSaY-b88HQpdDQzaAExZgjQClZH",
    "1Lw28hGU0Sy8zRRhNIZ6y2kmOYZJMxJqh",
    "1dXjq9D0txrSOuofFI2afvcm63o46LlR6",
    "1b3SOB7Kkh5vpAdY-SdPFTqrOvTI1J4jZ",
    "1pm-ZynyOhHPlRgrzgNvFQeIFeGfcA1Fi",
    "1SyHzl21hvSk-63F18ODMfuGnlE1ekZMa",
    "1LxI9v1f5h5iKT1WFLi2-3Ivg4So3wtNA",
]

print("Checking file info via Drive viewer page (HEAD request)...")
print(f"{'ID':<40} {'Size':>12}  Name/Type")
print("-" * 70)

for fid in IDS:
    url = f"https://drive.google.com/uc?export=download&id={fid}&confirm=t"
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="HEAD")
        with urllib.request.urlopen(req, timeout=10) as r:
            ct   = r.headers.get("Content-Type", "?")
            size = r.headers.get("Content-Length", "?")
            disp = r.headers.get("Content-Disposition", "")
            name = re.search(r'filename="([^"]+)"', disp)
            name = name.group(1) if name else "?"
            # Size in MB
            size_mb = f"{int(size)/1e6:.1f} MB" if size.isdigit() else size
            print(f"  {fid}  {size_mb:>10}  {name}  ({ct[:30]})")
    except Exception as e:
        # For large files, Drive redirects to a warning page
        # Check if it's a redirect to a download warning
        try:
            req2 = urllib.request.Request(url, headers=HEADERS)
            # Don't follow redirects
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            with opener.open(req2, timeout=10) as r:
                ct = r.headers.get("Content-Type","?")
                size = r.headers.get("Content-Length","?")
                disp = r.headers.get("Content-Disposition","")
                name = re.search(r'filename="([^"]+)"', disp)
                name = name.group(1) if name else "?"
                size_mb = f"{int(size)/1e6:.1f} MB" if str(size).isdigit() else size
                print(f"  {fid}  {size_mb:>10}  {name}  ({ct[:30]})")
        except Exception as e2:
            print(f"  {fid}  ERROR: {str(e2)[:50]}")
