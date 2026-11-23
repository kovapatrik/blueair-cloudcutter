"""Native credential setup, no AWS CLI required."""

from __future__ import annotations

import configparser

from blueair_cloudcutter import aws


def test_save_credentials_writes_standard_files(monkeypatch, tmp_path):
    creds = tmp_path / "credentials"
    config = tmp_path / "config"
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))

    path = aws.save_credentials(
        access_key="AKIATEST",
        secret_key="secret",
        region="eu-west-1",
        profile="default",
    )

    assert path == creds
    parsed = configparser.RawConfigParser()
    parsed.read(creds)
    assert parsed["default"]["aws_access_key_id"] == "AKIATEST"
    assert parsed["default"]["aws_secret_access_key"] == "secret"
    assert creds.stat().st_mode & 0o777 == 0o600

    parsed.read(config)
    assert parsed["default"]["region"] == "eu-west-1"


def test_save_credentials_named_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))

    aws.save_credentials(
        access_key="AKIATEST",
        secret_key="secret",
        session_token="token",
        region="us-east-1",
        profile="work",
    )

    parsed = configparser.RawConfigParser()
    parsed.read(tmp_path / "credentials")
    assert parsed["work"]["aws_session_token"] == "token"
    config = configparser.RawConfigParser()
    config.read(tmp_path / "config")
    assert config["profile work"]["region"] == "us-east-1"


def test_save_sso_profile_converts_to_legacy(monkeypatch, tmp_path):
    config = tmp_path / "config"
    config.write_text(
        "[profile work]\n"
        "sso_session = corp\n"
        "sso_account_id = 111122223333\n"
        "sso_role_name = Admin\n"
        "[sso-session corp]\n"
        "sso_start_url = https://example.awsapps.com/start\n"
        "sso_region = us-east-1\n"
    )
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))

    path = aws.save_sso_profile(
        profile="work",
        start_url="https://example.awsapps.com/start",
        sso_region="us-east-1",
        account_id="111122223333",
        role_name="Admin",
        region="eu-west-1",
    )

    parsed = configparser.RawConfigParser()
    parsed.read(path)
    assert not parsed.has_option("profile work", "sso_session")
    assert parsed["profile work"]["sso_start_url"] == "https://example.awsapps.com/start"
    assert parsed["profile work"]["region"] == "eu-west-1"


def test_save_sso_token_uses_botocore_cache_layout(monkeypatch, tmp_path):
    import hashlib
    import json

    monkeypatch.setenv("HOME", str(tmp_path))
    start_url = "https://example.awsapps.com/start"

    path = aws.save_sso_token(
        start_url=start_url,
        sso_region="us-east-1",
        access_token="token",
        expires_in=3600,
    )

    assert (
        path == tmp_path / ".aws" / "sso" / "cache" / f"{hashlib.sha1(start_url.encode()).hexdigest()}.json"
    )
    data = json.loads(path.read_text())
    assert data["accessToken"] == "token"
    assert data["startUrl"] == start_url
    assert data["expiresAt"].endswith("Z")


def test_sso_profiles_reads_legacy_and_session(monkeypatch, tmp_path):
    config = tmp_path / "config"
    config.write_text(
        "[default]\n"
        "region = eu-west-1\n"
        "[profile corp]\n"
        "sso_session = login\n"
        "sso_account_id = 111122223333\n"
        "sso_role_name = Admin\n"
        "[sso-session login]\n"
        "sso_start_url = https://example.awsapps.com/start\n"
        "sso_region = us-east-1\n"
        "[profile key]\n"
        "aws_access_key_id = AKIA\n"
    )
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))

    assert aws.sso_profiles() == ["corp"]


def test_sso_error_has_actionable_message():
    class UnauthorizedSSOTokenError(Exception):
        pass

    message = str(aws._wrap_aws(UnauthorizedSSOTokenError("expired")))
    assert "aws login --sso" in message


def test_setup_code_roundtrip():
    code = aws.encode_setup_code(access_key="AKIATEST", secret_key="secret/+==")
    data = aws.decode_setup_code(code)

    assert data["access_key_id"] == "AKIATEST"
    assert data["secret_access_key"] == "secret/+=="


def test_setup_code_tolerates_line_wraps():
    code = aws.encode_setup_code(access_key="AKIATEST", secret_key="secret")
    wrapped = code[:20] + "\n" + code[20:]

    assert aws.decode_setup_code(wrapped)["access_key_id"] == "AKIATEST"


def test_setup_code_rejects_junk():
    import pytest

    from blueair_cloudcutter.errors import CutterError

    with pytest.raises(CutterError):
        aws.decode_setup_code("not-a-code")


def test_resolve_region_from_profile(monkeypatch, tmp_path):
    config = tmp_path / "config"
    config.write_text("[default]\nregion = us-east-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    assert aws.resolve_region() == "us-east-1"
