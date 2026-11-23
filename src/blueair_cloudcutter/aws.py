"""AWS IoT onboarding for the no-UART path.

A user needs an AWS account and an IAM principal with programmatic credentials
and IoT permissions. The tool cannot create the account or the IAM user; it
uses boto3's normal credential chain (`aws configure`, env vars, SSO, profile).

`onboard` does the one-time work:

* describe the account's IoT endpoint,
* create/ensure a policy and a thing,
* register the device's captured client certificate and attach it,
* create a control identity (certificate + private key) for the tool,
* save the non-secret settings to `output/aws.json`.

Subsequent commands load that file automatically.
"""

from __future__ import annotations

import base64
import configparser
import datetime as dt
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .certs import certificate_pem_bytes
from .errors import CutterError
from .util import ok, read_json, write_json

DEFAULT_CONFIG = "aws.json"
IOT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iot:*", "Resource": "*"}],
}


@dataclass
class AwsConfig:
    region: str
    endpoint: str
    thing: str
    policy: str
    device_cert: str
    control_cert: str
    control_key: str
    control_name: str
    account: str = ""
    did: str = ""
    device_cert_arn: str = ""

    def save(self, path: Path) -> None:
        write_json(path, asdict(self))

    @classmethod
    def load(cls, path: Path) -> AwsConfig:
        raw = read_json(path, default=None)
        if not isinstance(raw, dict):
            raise CutterError(f"no AWS onboarding at {path}; run `blueair-cloudcutter aws onboard`")
        try:
            return cls(**{k: raw[k] for k in cls.__dataclass_fields__ if k in raw})
        except TypeError as exc:
            raise CutterError(f"bad AWS config at {path}: {exc}") from exc


def operator_home() -> Path:
    """The invoking user's home, even under sudo."""
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        try:
            import pwd

            return Path(pwd.getpwnam(user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def _hand_ownership(path: Path) -> None:
    uid = os.environ.get("HOST_UID") or os.environ.get("SUDO_UID")
    gid = os.environ.get("HOST_GID") or os.environ.get("SUDO_GID")
    if not (uid and gid) or os.geteuid() != 0:
        return
    # In a rootless container container-root already maps to the host user;
    # chowning to HOST_UID would map to a subuid and break the mount ownership.
    try:
        from .preflight import user_namespace_is_host

        if user_namespace_is_host() is False:
            return
    except Exception:  # noqa: BLE001 - best effort
        pass
    try:
        os.chown(path, int(uid), int(gid))
    except OSError:
        pass


def encode_setup_code(*, access_key: str, secret_key: str) -> str:
    payload = {"v": 1, "access_key_id": access_key, "secret_access_key": secret_key}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_setup_code(code: str) -> dict:
    code = "".join(code.split())
    try:
        padded = code + "=" * (-len(code) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
    except Exception as exc:
        raise CutterError(
            "that is not a blueair-cloudcutter setup code; copy the whole block printed by "
            "scripts/aws-bootstrap.sh"
        ) from exc
    if not isinstance(data, dict) or not data.get("access_key_id") or not data.get("secret_access_key"):
        raise CutterError("the setup code is missing the access key or secret")
    return data


def save_credentials(
    *,
    access_key: str,
    secret_key: str,
    session_token: str = "",
    region: str = "eu-west-1",
    profile: str = "default",
) -> Path:
    """Write the standard ~/.aws files, so no AWS CLI is required."""
    home = operator_home()
    cred_path = Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", str(home / ".aws" / "credentials")))
    conf_path = Path(os.environ.get("AWS_CONFIG_FILE", str(home / ".aws" / "config")))
    cred_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.parent.mkdir(parents=True, exist_ok=True)

    credentials = configparser.RawConfigParser()
    credentials.read(cred_path)
    section = profile or "default"
    if not credentials.has_section(section):
        credentials.add_section(section)
    credentials.set(section, "aws_access_key_id", access_key.strip())
    credentials.set(section, "aws_secret_access_key", secret_key.strip())
    if session_token:
        credentials.set(section, "aws_session_token", session_token.strip())
    else:
        credentials.remove_option(section, "aws_session_token")
    with cred_path.open("w") as handle:
        credentials.write(handle)
    cred_path.chmod(0o600)

    config = configparser.RawConfigParser()
    config.read(conf_path)
    config_section = "default" if section == "default" else f"profile {section}"
    if not config.has_section(config_section):
        config.add_section(config_section)
    config.set(config_section, "region", region)
    with conf_path.open("w") as handle:
        config.write(handle)
    conf_path.chmod(0o600)

    _hand_ownership(cred_path.parent)
    _hand_ownership(cred_path)
    _hand_ownership(conf_path)
    return cred_path


def sso_profile_section(profile: str) -> str:
    return "default" if profile == "default" else f"profile {profile}"


def existing_sso_config(profile: str) -> dict:
    """Read sso_start_url/region/account/role from ~/.aws/config."""
    path = Path(os.environ.get("AWS_CONFIG_FILE", str(operator_home() / ".aws" / "config")))
    config = configparser.RawConfigParser()
    config.read(path)
    section = sso_profile_section(profile)
    if not config.has_section(section):
        return {}
    data = dict(config[section])
    session = data.get("sso_session")
    if session:
        session_section = f"sso-session {session}"
        if config.has_section(session_section):
            for key in ("sso_start_url", "sso_region"):
                if not data.get(key):
                    data[key] = config[session_section].get(key, "")
    return data


def sso_profiles() -> list[str]:
    path = Path(os.environ.get("AWS_CONFIG_FILE", str(operator_home() / ".aws" / "config")))
    config = configparser.RawConfigParser()
    config.read(path)
    names: list[str] = []
    for section in config.sections():
        if section.startswith("sso-session "):
            continue
        data = config[section]
        if data.get("sso_start_url") or data.get("sso_session"):
            names.append("default" if section == "default" else section.removeprefix("profile "))
    return names


def save_sso_profile(
    *,
    profile: str,
    start_url: str,
    sso_region: str,
    account_id: str,
    role_name: str,
    region: str,
) -> Path:
    path = Path(os.environ.get("AWS_CONFIG_FILE", str(operator_home() / ".aws" / "config")))
    path.parent.mkdir(parents=True, exist_ok=True)
    config = configparser.RawConfigParser()
    config.read(path)
    section = sso_profile_section(profile)
    if not config.has_section(section):
        config.add_section(section)
    # Use the legacy profile shape; botocore and the AWS CLI both support it.
    config.remove_option(section, "sso_session")
    config.set(section, "sso_start_url", start_url)
    config.set(section, "sso_region", sso_region)
    config.set(section, "sso_account_id", account_id)
    config.set(section, "sso_role_name", role_name)
    config.set(section, "region", region)
    with path.open("w") as handle:
        config.write(handle)
    path.chmod(0o600)
    _hand_ownership(path)
    return path


def save_sso_token(*, start_url: str, sso_region: str, access_token: str, expires_in: int) -> Path:
    cache = operator_home() / ".aws" / "sso" / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha1(start_url.encode()).hexdigest()
    path = cache / f"{key}.json"
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=expires_in)
    path.write_text(
        json.dumps(
            {
                "accessToken": access_token,
                "expiresAt": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "region": sso_region,
                "startUrl": start_url,
            }
        )
    )
    path.chmod(0o600)
    _hand_ownership(cache)
    _hand_ownership(path)
    return path


def sso_start_device_login(start_url: str, sso_region: str) -> dict:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover
        raise CutterError(
            "boto3 is not installed. Install the AWS extra: pip install 'blueair-cloudcutter[aws]'"
        ) from exc
    try:
        oidc = boto3.client("sso-oidc", region_name=sso_region)
        registration = oidc.register_client(clientName="blueair-cloudcutter", clientType="public")
        auth = oidc.start_device_authorization(
            clientId=registration["clientId"],
            clientSecret=registration["clientSecret"],
            startUrl=start_url,
        )
    except Exception as exc:
        raise CutterError(f"SSO device authorization failed: {exc}") from exc
    return {
        "client": oidc,
        "client_id": registration["clientId"],
        "client_secret": registration["clientSecret"],
        "device_code": auth["deviceCode"],
        "user_code": auth["userCode"],
        "verification_uri": auth["verificationUri"],
        "verification_uri_complete": auth.get("verificationUriComplete") or auth["verificationUri"],
        "interval": max(1, int(auth.get("interval", 5))),
        "expires_in": int(auth["expiresIn"]),
    }


def sso_wait_for_token(auth: dict) -> dict:
    oidc = auth["client"]
    deadline = time.time() + auth["expires_in"]
    interval = auth["interval"]
    while time.time() < deadline:
        try:
            return oidc.create_token(
                clientId=auth["client_id"],
                clientSecret=auth["client_secret"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=auth["device_code"],
            )
        except oidc.exceptions.AuthorizationPendingException:
            time.sleep(interval)
        except oidc.exceptions.SlowDownException:
            interval += 5
            time.sleep(interval)
        except oidc.exceptions.ExpiredTokenException as exc:
            raise CutterError("SSO device authorization expired; run `aws login --sso` again") from exc
        except oidc.exceptions.AccessDeniedException as exc:
            raise CutterError("SSO login was denied") from exc
        except Exception as exc:
            raise CutterError(f"SSO token request failed: {exc}") from exc
    raise CutterError("timed out waiting for the browser approval")


def sso_list_accounts(access_token: str, sso_region: str) -> list[dict]:
    import boto3

    sso = boto3.client("sso", region_name=sso_region)
    accounts: list[dict] = []
    token = None
    while True:
        kwargs = {"accessToken": access_token, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        response = sso.list_accounts(**kwargs)
        accounts.extend(response.get("accountList", []))
        token = response.get("nextToken")
        if not token:
            return accounts


def sso_list_roles(access_token: str, account_id: str, sso_region: str) -> list[dict]:
    import boto3

    sso = boto3.client("sso", region_name=sso_region)
    roles: list[dict] = []
    token = None
    while True:
        kwargs = {"accessToken": access_token, "accountId": account_id, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        response = sso.list_account_roles(**kwargs)
        roles.extend(response.get("roleList", []))
        token = response.get("nextToken")
        if not token:
            return roles


def validate_credentials(
    *, access_key: str, secret_key: str, session_token: str = "", region: str = "eu-west-1"
) -> dict:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise CutterError(
            "boto3 is not installed. Install the AWS extra: pip install 'blueair-cloudcutter[aws]'"
        ) from exc
    try:
        session = boto3.Session(
            aws_access_key_id=access_key.strip(),
            aws_secret_access_key=secret_key.strip(),
            aws_session_token=session_token.strip() or None,
            region_name=region,
        )
        return session.client("sts").get_caller_identity()
    except Exception as exc:
        raise CutterError(f"AWS rejected these credentials: {exc}") from exc


def default_path(output: Path) -> Path:
    return output / DEFAULT_CONFIG


def load_default(output: Path) -> AwsConfig | None:
    path = default_path(output)
    if not path.exists():
        return None
    return AwsConfig.load(path)


def resolve_region(profile: str | None = None) -> str | None:
    """The region from the AWS login/profile, not a CLI default."""
    env = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if env:
        return env
    path = Path(os.environ.get("AWS_CONFIG_FILE", str(operator_home() / ".aws" / "config")))
    config = configparser.RawConfigParser()
    config.read(path)
    section = sso_profile_section(profile or "default")
    if config.has_section(section):
        region = config[section].get("region")
        if region:
            return region
    try:
        import boto3

        session_obj = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session_obj.region_name
    except Exception:  # noqa: BLE001 - optional dependency / no region
        return None


def session(region: str | None, profile: str | None = None):
    """A boto3 session using the normal credential chain."""
    return _boto(region, profile)


def _boto(region: str, profile: str | None = None):
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise CutterError(
            "boto3 is not installed. Install the AWS extra: pip install 'blueair-cloudcutter[aws]'"
        ) from exc
    session = (
        boto3.Session(profile_name=profile, region_name=region)
        if profile
        else boto3.Session(region_name=region)
    )
    return session


def _wrap_aws(exc: Exception) -> CutterError:
    name = type(exc).__name__
    if "SSO" in name or "Unauthorized" in name:
        return CutterError(
            f"AWS SSO session is missing or expired ({name}). Run `blueair-cloudcutter aws login --sso`."
        )
    return CutterError(
        f"AWS call failed: {exc}. Check your credentials, region and IoT permissions "
        "(`blueair-cloudcutter aws login`, or `aws check`)."
    )


def check(region: str | None = None, profile: str | None = None) -> dict:
    region = region or resolve_region(profile) or "eu-west-1"
    try:
        session = _boto(region, profile)
        sts = session.client("sts")
        iot = session.client("iot")
        ident = sts.get_caller_identity()
        endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    except CutterError:
        raise
    except Exception as exc:  # botocore/boto3 errors are not a hard dependency here
        raise _wrap_aws(exc) from exc
    return {
        "account": ident["Account"],
        "arn": ident["Arn"],
        "region": region,
        "endpoint": endpoint,
    }


def _ensure_policy(iot, name: str) -> None:
    try:
        iot.get_policy(policyName=name)
    except iot.exceptions.ResourceNotFoundException:
        iot.create_policy(policyName=name, policyDocument=json.dumps(IOT_POLICY))
        ok(f"created IoT policy {name}")


def _ensure_thing(iot, name: str) -> None:
    try:
        iot.describe_thing(thingName=name)
    except iot.exceptions.ResourceNotFoundException:
        iot.create_thing(thingName=name)
        ok(f"created IoT thing {name}")


def _cert_id(pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(pem)
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _name_suffix(cert_id: str) -> str:
    return cert_id[:12] if cert_id else "unknown"


def default_thing_name(cert_id: str) -> str:
    """A per-device thing name (the certificate is the identity)."""
    return f"blueair-device-{_name_suffix(cert_id)}"


def default_control_name(cert_id: str) -> str:
    """A per-device control identity, so two devices never share a client."""
    return f"blueair-controller-{_name_suffix(cert_id)}"


def onboard(
    *,
    output: Path,
    device_cert: Path,
    thing: str | None = None,
    region: str | None = None,
    policy: str = "blueair-policy",
    control_name: str | None = None,
    profile: str | None = None,
) -> AwsConfig:
    if not device_cert.exists():
        raise CutterError(f"device certificate not found: {device_cert}")
    region = region or resolve_region(profile) or "eu-west-1"
    certificate_pem_bytes(device_cert)  # validate before touching AWS

    try:
        cfg = _onboard(
            output=output,
            device_cert=device_cert,
            thing=thing,
            region=region,
            policy=policy,
            control_name=control_name,
            profile=profile,
        )
        from . import devices

        devices.upsert(output, cfg)
        return cfg
    except CutterError:
        raise
    except Exception as exc:
        raise _wrap_aws(exc) from exc


def _onboard(
    *,
    output: Path,
    device_cert: Path,
    thing: str | None,
    region: str,
    policy: str,
    control_name: str | None,
    profile: str | None,
) -> AwsConfig:
    pem = certificate_pem_bytes(device_cert)
    session = _boto(region, profile)
    sts = session.client("sts")
    iot = session.client("iot")
    account = sts.get_caller_identity()["Account"]
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    cert_id = _cert_id(pem)
    thing = thing or default_thing_name(cert_id)
    control_name = control_name or default_control_name(cert_id)

    _ensure_policy(iot, policy)
    _ensure_thing(iot, thing)

    try:
        arn = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["certificateArn"]
        iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
        ok(f"device certificate already registered; active: {arn}")
    except iot.exceptions.ResourceNotFoundException:
        arn = iot.register_certificate_without_ca(certificatePem=pem.decode(), status="ACTIVE")[
            "certificateArn"
        ]
        ok(f"registered device certificate: {arn}")

    iot.attach_policy(policyName=policy, target=arn)
    iot.attach_thing_principal(thingName=thing, principal=arn)
    ok(f"attached the device certificate to thing {thing}")

    _ensure_thing(iot, control_name)
    created = iot.create_keys_and_certificate(setAsActive=True)
    control_arn = created["certificateArn"]
    iot.attach_policy(policyName=policy, target=control_arn)
    iot.attach_thing_principal(thingName=control_name, principal=control_arn)

    device_dir = output.resolve() / "devices" / cert_id
    device_dir.mkdir(parents=True, exist_ok=True)
    device_copy = device_dir / "device.pem"
    if device_copy.resolve() != device_cert.resolve() or device_copy.read_bytes() != pem:
        device_copy.write_bytes(pem)
    control_cert = device_dir / "control.cert.pem"
    control_key = device_dir / "control.private.key"
    control_cert.write_text(created["certificatePem"])
    control_key.write_text(created["keyPair"]["PrivateKey"])
    control_key.chmod(0o600)
    (device_dir / "control.public.key").write_text(created["keyPair"]["PublicKey"])

    cfg = AwsConfig(
        region=region,
        endpoint=endpoint,
        thing=thing,
        policy=policy,
        device_cert=str(device_copy.resolve()),
        control_cert=str(control_cert.resolve()),
        control_key=str(control_key.resolve()),
        control_name=control_name,
        account=account,
        device_cert_arn=arn,
    )
    cfg.save(default_path(output))
    ok(f"AWS onboarding saved to {default_path(output)}")
    return cfg


def apply_defaults(output: Path, args) -> AwsConfig | None:
    """Fill broker/cert/key/did from output/aws.json when the CLI omitted them."""
    cfg = load_default(output)
    if cfg is None:
        return None
    if not getattr(args, "broker", None):
        args.broker = cfg.endpoint
    if not getattr(args, "cert", None):
        args.cert = Path(cfg.control_cert)
    if not getattr(args, "key", None):
        args.key = Path(cfg.control_key)
    if not getattr(args, "did", None) and cfg.did:
        args.did = cfg.did
    return cfg


def format_config(cfg: AwsConfig) -> str:
    return "\n".join(
        [
            f"account:      {cfg.account or '?'}",
            f"region:       {cfg.region}",
            f"endpoint:     {cfg.endpoint}",
            f"thing:        {cfg.thing}",
            f"policy:       {cfg.policy}",
            f"device cert:  {cfg.device_cert}",
            f"control cert: {cfg.control_cert}",
            f"control key:  {cfg.control_key}",
            f"DID:          {cfg.did or '(not discovered yet)'}",
        ]
    )
