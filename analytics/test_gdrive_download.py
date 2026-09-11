import urllib.request, re, os

FILE_ID = "17TOT65H_Zml2FKRJbi-tfPMay0n4XzUu"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def get_confirm_url(file_id):
    """Get the confirmed download URL for large Google Drive files."""
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as r:
        ct = r.headers.get("Content-Type","")
        if "text/html" in ct:
            body = r.read(10000).decode("utf-8","ignore")
            # Find confirm token
            m = re.search(r'confirm=([A-Za-z0-9_\-]+)', body)
            token = m.group(1) if m else "t"
            return f"https://drive.google.com/uc?export=download&id={file_id}&confirm={token}"
        else:
            # Direct download already
            size = r.headers.get("Content-Length","?")
            name = re.search(r'filename="([^"]+)"', r.headers.get("Content-Disposition",""))
            print(f"Direct: {name.group(1) if name else '?'}  {size} bytes")
            return url

print(f"Testing file ID: {FILE_ID}")
try:
    dl_url = get_confirm_url(FILE_ID)
    print(f"Download URL: {dl_url}")
    
    # Check headers only (don't download the whole file)
    req = urllib.request.Request(dl_url, headers=HEADERS, method="HEAD")
    with urllib.request.urlopen(req, timeout=10) as r:
        ct   = r.headers.get("Content-Type","?")
        size = r.headers.get("Content-Length","?")
        disp = r.headers.get("Content-Disposition","")
        name = re.search(r'filename="([^"]+)"', disp)
        print(f"Name:  {name.group(1) if name else '?'}")
        print(f"Size:  {int(size)/1e6:.1f} MB" if size.isdigit() else f"Size: {size}")
        print(f"Type:  {ct}")
        print("✅ File accessible!")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback; traceback.print_exc()
