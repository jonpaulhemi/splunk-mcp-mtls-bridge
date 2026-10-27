"""The daemon reports the version of the app it was installed as."""

import json
import shutil
import subprocess
import sys

from harness import ROOT


def test_version_comes_from_the_installed_apps_manifest(tmp_path):
    # ucc-gen stamps the release tag's version into app.manifest; the daemon reports what it finds there.
    app = tmp_path / "TA-mtls-bridge"
    shutil.copytree(ROOT / "package" / "bin", app / "bin")
    manifest = json.loads((ROOT / "package" / "app.manifest").read_text())
    manifest["info"]["id"]["version"] = "9.8.7"
    (app / "app.manifest").write_text(json.dumps(manifest))

    code = "import mtls_bridge; print(mtls_bridge.__version__)"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", f"import sys; sys.path.insert(0, 'bin'); {code}"],
        cwd=str(app),
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "9.8.7", result.stderr
