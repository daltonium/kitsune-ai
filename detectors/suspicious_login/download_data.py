"""Download only what Phase 8 needs from a CERT r4.2 mirror on Hugging Face (about 60 MB).

    python -m detectors.suspicious_login.download_data
Official full archive (4.8 GB): https://doi.org/10.1184/R1/12841247.v1
"""
from pathlib import Path

from huggingface_hub import hf_hub_download, list_repo_files

REPO = "jinmang2/cert_insider_threat"
DEST = Path(__file__).resolve().parents[2] / "datasets" / "cert_r4_2"


def wanted(path: str) -> bool:
    return (
        path in ("r4.2/logon.csv", "r4.2/readme.txt", "answers/insiders.csv")
        or path.startswith("answers/r4.2-")
    )


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    files = list_repo_files(REPO, repo_type="dataset")
    chosen = sorted(f for f in files if wanted(f))
    if not chosen:
        print("No matching files. Top-level entries available:")
        print(sorted({f.split("/")[0] for f in files}))
        raise SystemExit(1)
    print(f"Downloading {len(chosen)} files into {DEST}")
    for name in chosen:
        hf_hub_download(REPO, name, repo_type="dataset", local_dir=str(DEST))
        print("  got", name)
    print("Done.")


if __name__ == "__main__":
    main()