import os
from pathlib import Path


ROOT = Path(os.environ.get("PROJECT_ROOT", Path(__file__).resolve().parents[2]))


def test_no_secret_material_is_committed():
    forbidden = {"kms_aes_key", "kms_signing_key.pem", "db_admin_password", "backup_ssh_key"}
    tracked_names = {path.name for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts}
    assert not (forbidden & tracked_names)


def test_vulnerable_lab_has_no_secure_volume_mounts():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    section = compose.split("  vulnerable-lab:", 1)[1].split("  attack-runner:", 1)[0]
    assert "postgres_data" not in section
    assert "secrets:" not in section
    assert "certs:" not in section
    assert "profiles: [lab]" in section


def test_only_gateway_publishes_the_public_https_port():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert compose.count("${PUBLIC_HTTPS_PORT:-8443}:8443") == 1
