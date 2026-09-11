import sys
sys.path.insert(0, ".")

# Quick test - just verify the download starts correctly
import gdown, os, inspect

FILE_ID = "17TOT65H_Zml2FKRJbi-tfPMay0n4XzUu"
url = "https://drive.google.com/uc?id=" + FILE_ID
out_path = "test_warehouse_small.tmp"

print(f"gdown version: {gdown.__version__}")
print(f"Signature: {inspect.signature(gdown.download)}")
print(f"Testing download from: {url}")

kwargs = {"quiet": False}
sig = inspect.signature(gdown.download)
if "fuzzy" in sig.parameters:
    kwargs["fuzzy"] = True

try:
    result = gdown.download(url, out_path, **kwargs)
    if result and os.path.exists(out_path):
        size = os.path.getsize(out_path)
        print(f"SUCCESS: Downloaded {size/1e6:.1f} MB to {out_path}")
        # Clean up
        os.remove(out_path)
    else:
        print("FAILED: No output file")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback; traceback.print_exc()
