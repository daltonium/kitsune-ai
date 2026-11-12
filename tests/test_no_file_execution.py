from pathlib import Path

from detectors.network_intrusion.predictor import NetworkIntrusionDetector
from detectors.network_intrusion.tests.synthetic import FakeUpload, make_flows

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = ("subprocess", "os.system", "os.popen", "eval(", "exec(", "ctypes", "pickle.loads")


def test_no_execution_primitives_in_detectors():
    for path in (ROOT / "detectors").rglob("*.py"):
        if "tests" in path.parts:
            continue
        hits = [s for s in FORBIDDEN if s in path.read_text(encoding="utf-8")]
        assert not hits, (path.name, hits)


def test_csv_upload_never_touches_disk(monkeypatch, tmp_path, network_artifacts):
    monkeypatch.chdir(tmp_path)
    X, _ = make_flows(10, seed=3)
    NetworkIntrusionDetector(artifacts_dir=network_artifacts).analyze(
        {"file": FakeUpload(X.to_csv(index=False).encode())})
    assert list(tmp_path.iterdir()) == []