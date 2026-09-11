"""Scan all Drive IDs to find the large duckdb file."""
import urllib.request, re

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

ALL_IDS = [
    "1c1T84Z1Vy5xDKLxw6V6IassbsXYyPU1I","1He3k_3i1SviYFZRnh17Py-K9Dwd0Wjf0",
    "11pO5jmSaY-b88HQpdDQzaAExZgjQClZH","1Lw28hGU0Sy8zRRhNIZ6y2kmOYZJMxJqh",
    "1dXjq9D0txrSOuofFI2afvcm63o46LlR6","1b3SOB7Kkh5vpAdY-SdPFTqrOvTI1J4jZ",
    "1pm-ZynyOhHPlRgrzgNvFQeIFeGfcA1Fi","1SyHzl21hvSk-63F18ODMfuGnlE1ekZMa",
    "1LxI9v1f5h5iKT1WFLi2-3Ivg4So3wtNA","1f9D1mqjocOaDqvYDoZLfv3W2wRY03wUX",
    "1a-2cN2J9GA0RqundjsKWbrWKiFbk2qk-","1kg6wzi11ppdPtNtiw3wBWrOy0taUQGdX",
    "1UIu1scIiQshWlx4WnsiMF0EY4ez5HYhJ","1nj20TQX-3F0zdgu7jNN00v0mku7nCXTz",
    "1p6PaAszMjxGvfFJfjwafpymUTXKwXQVY","11KKbwU6XpB6o32bVSinMezDleYmWo3dg",
    "1OgQD28fYxpESsRsFcVBUmQnseCh3IUhp","1w7N1NMhljkqhUuG11u9BU79kRiTn4tdi",
    "12M6FiLxC9v1fDRHuhW5t7QdJk8VPTPop","103U-aV1KWww8sQB8AcGdjdc6AO4tduvt",
    "1YkhZl-C96oGVtfNbJX36hPw6sUnVhp8A","1McItwlN2BPShxZ_rng-c9ZCpuzmjM1jT",
    "1EWdF1UvtN552OvfRSAFDBpE7QaI9IVbj","1PmYyPdWZIDn-pEBToqA2Z7ceHXusPYRO",
    "15u4nGrWfQQ_6_0Aq5KZnQViJ2salBarx","1J2kM2tXPMbY-PfVBCqf09DijXUFhEDBZ",
    "10gYbPRC30zXQ-aniHRm99hUH1MUBeS39","1iXi8_1GbN4KGVVi9hbojr7DuOYieoiY2",
    "1qPFOwCLlFdc-7qBFej3WCZ4jG-I9hD_D",
]

print(f"Scanning {len(ALL_IDS)} files for the large .duckdb...\n")
duckdb_id = None

for fid in ALL_IDS:
    url = f"https://drive.google.com/uc?export=download&id={fid}&confirm=t"
    try:
        req = urllib.request.Request(url, headers=HEADERS, method="HEAD")
        with urllib.request.urlopen(req, timeout=8) as r:
            ct   = r.headers.get("Content-Type", "")
            size = r.headers.get("Content-Length", "0")
            disp = r.headers.get("Content-Disposition", "")
            name_m = re.search(r'filename="([^"]+)"', disp)
            name = name_m.group(1) if name_m else ""
            size_mb = int(size) / 1e6 if size.isdigit() else 0
            
            if size_mb > 5 or "duckdb" in name.lower():
                print(f"★ LARGE/DUCKDB: {fid}")
                print(f"  Name: {name}  Size: {size_mb:.1f} MB  Type: {ct}")
                print(f"  URL: https://drive.google.com/uc?export=download&id={fid}&confirm=t")
                duckdb_id = fid
            else:
                print(f"  {fid}  {size_mb:5.1f}MB  {name[:40]}")
    except Exception as e:
        print(f"  {fid}  REDIRECT/ERROR (likely large file needing confirm)")
        # Large files get redirected to virus scan warning - this is probably our file
        # Check by fetching the warning page
        try:
            req2 = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req2, timeout=8) as r2:
                body = r2.read(2000).decode("utf-8","ignore")
                if "duckdb" in body.lower() or "uc-download-link" in body:
                    print(f"  ★ FOUND LARGE FILE (virus scan page): {fid}")
                    duckdb_id = fid
        except Exception:
            pass

print(f"\nDuckDB file ID: {duckdb_id}")
if duckdb_id:
    print(f"Direct URL: https://drive.google.com/uc?export=download&id={duckdb_id}&confirm=t")
