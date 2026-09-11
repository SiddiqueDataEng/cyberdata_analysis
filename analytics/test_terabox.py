"""Test Terabox link resolution."""
import urllib.request, json, re, sys

SHARE_URL = "https://1024terabox.com/s/1BE3pqdUS4Ueo-aQeZ1W-tw"
SURL = "1BE3pqdUS4Ueo-aQeZ1W-tw"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, */*",
    "Referer": "https://1024terabox.com/",
}

endpoints = [
    f"https://www.terabox.com/api/shorturlinfo?app_id=250528&shorturl={SURL}&root=1",
    f"https://1024terabox.com/api/shorturlinfo?app_id=250528&shorturl={SURL}&root=1",
    f"https://teraboxapp.com/api/shorturlinfo?app_id=250528&shorturl={SURL}&root=1",
]

print("Testing Terabox API endpoints...")
direct_url = None

for ep in endpoints:
    print(f"\nTrying: {ep}")
    try:
        req = urllib.request.Request(ep, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8")
        data = json.loads(raw)
        print(f"  errno: {data.get('errno')}")
        print(f"  Keys: {list(data.keys())}")
        if data.get("errno") == 0:
            for key in ("list","file_list","file_info"):
                items = data.get(key, [])
                if isinstance(items, dict):
                    items = items.get("list", [])
                for item in items:
                    print(f"  File: {item.get('server_filename','?')} size={item.get('size','?')}")
                    for dk in ("dlink","download_link","url"):
                        link = item.get(dk,"")
                        if link:
                            print(f"  DIRECT URL found via {dk}: {link[:80]}...")
                            direct_url = link
            break
        else:
            print(f"  Raw: {raw[:200]}")
    except Exception as e:
        print(f"  ERROR: {e}")

if not direct_url:
    print("\n\nAPI failed. Trying page scrape...")
    try:
        req = urllib.request.Request(SHARE_URL, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=20) as r:
            html = r.read().decode("utf-8", errors="ignore")
        print(f"  Page length: {len(html)} chars")
        for pat in [r'"dlink"\s*:\s*"(https?://[^"]+)"',
                    r'"download_link"\s*:\s*"(https?://[^"]+)"',
                    r'(https?://[^"\'<\s]+\.duckdb[^"\'<\s]*)']:
            m = re.search(pat, html)
            if m:
                print(f"  Found via scrape: {m.group(1)[:100]}")
    except Exception as e:
        print(f"  Scrape error: {e}")

print("\nDone.")
