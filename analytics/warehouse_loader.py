"""
Downloads cyber_warehouse.duckdb from Terabox on Streamlit Cloud startup.
Uses Terabox's public share API — no login required.
"""
import os
import sys
import urllib.request
import urllib.parse
import json
import re
import time
from pathlib import Path


# ── Terabox share URL ─────────────────────────────────────────────────────────
TERABOX_SHARE_URL = "https://1024terabox.com/s/1BE3pqdUS4Ueo-aQeZ1W-tw"

# ── Fallback: try multiple Terabox API endpoints ──────────────────────────────
TERABOX_API_URLS = [
    "https://www.terabox.com/api/shorturlinfo?app_id=250528&shorturl={surl}&root=1",
    "https://1024terabox.com/api/shorturlinfo?app_id=250528&shorturl={surl}&root=1",
    "https://teraboxapp.com/api/shorturlinfo?app_id=250528&shorturl={surl}&root=1",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://1024terabox.com/",
}


def _extract_surl(share_url: str) -> str:
    """Extract the short URL token from a Terabox share link."""
    # e.g. https://1024terabox.com/s/1BE3pqdUS4Ueo-aQeZ1W-tw → 1BE3pqdUS4Ueo-aQeZ1W-tw
    m = re.search(r"/s/([A-Za-z0-9_\-]+)", share_url)
    return m.group(1) if m else share_url.rstrip("/").split("/")[-1]


def _get_direct_url_via_api(surl: str) -> str | None:
    """Query Terabox API to get the direct download URL."""
    for api_template in TERABOX_API_URLS:
        url = api_template.format(surl=surl)
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            # Navigate the API response
            if data.get("errno") != 0:
                continue

            # Look for dlink (direct link) in file list
            file_list = (
                data.get("list") or
                data.get("file_list") or
                (data.get("file_info") or {}).get("list") or
                []
            )
            for item in file_list:
                dlink = item.get("dlink") or item.get("download_link") or item.get("url")
                if dlink:
                    return dlink
        except Exception:
            continue
    return None


def _get_direct_url_via_scrape(share_url: str) -> str | None:
    """Fallback: scrape the share page for a download link."""
    try:
        req = urllib.request.Request(share_url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        patterns = [
            r'"dlink"\s*:\s*"(https?://[^"]+)"',
            r'"download_link"\s*:\s*"(https?://[^"]+)"',
            r'downloadUrl\s*=\s*["\']?(https?://[^\s"\'<]+)',
        ]
        for pat in patterns:
            m = re.search(pat, html)
            if m:
                url = m.group(1).replace("\\u0026", "&").replace("\\/", "/")
                if url.startswith("http"):
                    return url
    except Exception:
        pass
    return None


def download_warehouse(db_path: str, progress_cb=None) -> bool:
    """
    Download the DuckDB warehouse file to db_path.
    progress_cb(pct: int, msg: str) — optional callback for UI updates.
    Returns True on success.
    """
    def _prog(pct, msg):
        if progress_cb:
            progress_cb(pct, msg)

    _prog(5, "🔗 Resolving Terabox share link…")
    surl = _extract_surl(TERABOX_SHARE_URL)

    # Try API first
    _prog(10, "🌐 Querying Terabox API for direct link…")
    direct_url = _get_direct_url_via_api(surl)

    # Fallback to scraping
    if not direct_url:
        _prog(15, "🔍 Trying page scrape for download link…")
        direct_url = _get_direct_url_via_scrape(TERABOX_SHARE_URL)

    if not direct_url:
        return False

    # Download with progress
    _prog(20, "⬇️ Downloading warehouse file…")
    tmp = db_path + ".tmp"
    try:
        req = urllib.request.Request(direct_url, headers=HEADERS)
        chunk = 1024 * 512  # 512 KB
        downloaded = 0
        with urllib.request.urlopen(req, timeout=180) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            with open(tmp, "wb") as f:
                while True:
                    data = resp.read(chunk)
                    if not data:
                        break
                    f.write(data)
                    downloaded += len(data)
                    if total > 0:
                        pct = min(95, 20 + int(downloaded / total * 75))
                        mb_done = downloaded / 1_048_576
                        mb_total = total / 1_048_576
                        _prog(pct, f"⬇️ Downloading… {mb_done:.0f} / {mb_total:.0f} MB")

        if os.path.getsize(tmp) < 10_000:
            os.remove(tmp)
            return False

        os.replace(tmp, db_path)
        _prog(100, "✅ Download complete!")
        return True

    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError(f"Download failed: {e}") from e


def build_from_ndjson(db_path: str, data_dir: str, progress_cb=None) -> None:
    """Build DuckDB warehouse from NDJSON files."""
    def _prog(pct, msg):
        if progress_cb:
            progress_cb(pct, msg)

    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))

    from importlib.util import spec_from_file_location, module_from_spec

    def _load(alias, fname):
        spec = spec_from_file_location(alias, here / fname)
        mod  = module_from_spec(spec)
        sys.modules[alias] = mod
        spec.loader.exec_module(mod)
        return mod

    _prog(10, "📂 Running ETL: loading NDJSON files…")
    etl = _load("_etl_build", "01_etl.py")
    etl.run_etl(verbose=False)

    _prog(75, "📊 Building analytical marts…")
    an = _load("_analytical_build", "02_analytical.py")
    an.run_analytical(verbose=False)

    _prog(100, "✅ Warehouse built from NDJSON files!")
