"""AWS IoT onboarding and DID discovery."""

from __future__ import annotations

import getpass
import webbrowser
from pathlib import Path

from .. import aws, devices
from ..context import Context
from ..errors import CutterError
from ..mqttclient import MQTT, MQTTConfig
from ..preflight import in_docker
from ..util import extract_uuid, info, ok, step


def _choose(title: str, items: list[dict], label) -> dict:
    if len(items) == 1:
        return items[0]
    for index, item in enumerate(items, 1):
        print(f"  {index}) {label(item)}")
    while True:
        answer = input(f"{title} [1]: ").strip() or "1"
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            return items[int(answer) - 1]


def _sso_login(ctx: Context, args) -> int:
    profile = args.profile
    if not profile:
        profiles = aws.sso_profiles()
        profile = profiles[0] if len(profiles) == 1 else "blueair"
    existing = aws.existing_sso_config(profile)

    start_url = args.sso_start_url or existing.get("sso_start_url", "")
    sso_region = args.sso_region or existing.get("sso_region", "")
    if not start_url:
        start_url = input("IAM Identity Center start URL (https://.../start): ").strip()
    if not start_url:
        raise CutterError("an SSO start URL is required")
    if not sso_region:
        sso_region = input("SSO region [us-east-1]: ").strip() or "us-east-1"

    step(1, 3, "Start the browser login")
    auth = aws.sso_start_device_login(start_url, sso_region)
    info("Open this URL in your browser:")
    print(f"    {auth['verification_uri_complete']}")
    print(f"    code: {auth['user_code']}")
    if not args.no_browser and not in_docker():
        try:
            webbrowser.open(auth["verification_uri_complete"])
        except Exception:  # noqa: BLE001 - no browser is fine
            pass
    info("waiting for approval ...")
    token = aws.sso_wait_for_token(auth)
    access_token = token["accessToken"]

    step(2, 3, "Choose the account and role")
    account_id = args.sso_account or existing.get("sso_account_id", "")
    role_name = args.sso_role or existing.get("sso_role_name", "")
    if not account_id:
        accounts = aws.sso_list_accounts(access_token, sso_region)
        if not accounts:
            raise CutterError("this SSO user has no AWS accounts; check IAM Identity Center")
        account_id = _choose(
            "account", accounts, lambda item: f"{item['accountId']}  {item.get('accountName', '')}"
        )["accountId"]
    if not role_name:
        roles = aws.sso_list_roles(access_token, account_id, sso_region)
        if not roles:
            raise CutterError(f"no roles for account {account_id}")
        role_name = _choose("role", roles, lambda item: item["roleName"])["roleName"]

    step(3, 3, "Save the profile and validate")
    region = args.region or aws.resolve_region(profile) or "eu-west-1"
    path = aws.save_sso_profile(
        profile=profile,
        start_url=start_url,
        sso_region=sso_region,
        account_id=account_id,
        role_name=role_name,
        region=region,
    )
    cache = aws.save_sso_token(
        start_url=start_url,
        sso_region=sso_region,
        access_token=access_token,
        expires_in=int(token.get("expiresIn", 3600)),
    )
    (ctx.output / "aws-profile").write_text(profile + "\n")
    ok(f"profile {profile!r} -> {path}")
    ok(f"token cache -> {cache}")

    ident = aws.session(region, profile).client("sts").get_caller_identity()
    ok(f"account {ident['Account']}  {ident['Arn']}")
    if profile != "default":
        info(f"use it with --profile {profile} or export AWS_PROFILE={profile}")
    info("next: blueair-cloudcutter aws check")
    return 0


def _load(ctx: Context) -> aws.AwsConfig:
    return aws.AwsConfig.load(aws.default_path(ctx.output))


def _select(ctx: Context, args) -> None:
    selector = getattr(args, "device", None) or getattr(args, "did", None)
    if selector:
        record = devices.select(devices.load(ctx.output), selector)
        devices.activate(ctx.output, record)
        ok(f"selected {record.label}")


def run(ctx: Context, args) -> int:
    action = args.action

    if action == "devices":
        records = devices.load(ctx.output)
        print(devices.format_table(records))
        return 0

    if action == "check":
        step(1, 1, "Check AWS credentials and IoT endpoint")
        result = aws.check(args.region, args.profile)
        ok(f"account {result['account']}")
        info(f"arn:      {result['arn']}")
        info(f"region:   {result['region']}")
        info(f"endpoint: {result['endpoint']}")
        return 0

    if action == "guide":
        bootstrap = (
            "https://raw.githubusercontent.com/kovapatrik/blueair-cloudcutter/main/scripts/aws-bootstrap.sh"
        )
        print(
            f"""
AWS login for a personal account (the usual case):

1) Create an AWS account if you do not have one:
     https://portal.aws.amazon.com/billing/signup

2) Sign in to the console and open CloudShell:
     https://console.aws.amazon.com/cloudshell/home
   Paste this one command:

     curl -fsSL {bootstrap} | bash

   It prints one setup code.

3) On the Pi, paste that code:
     ./blueair-cloudcutter.sh aws login

No AWS CLI and no IAM console work: the bootstrap creates a dedicated IAM user
with the minimum permissions and wraps the key into the setup code.

If your organization uses IAM Identity Center, run `aws login --sso` instead.
The no-UART path needs an AWS account, or a hosted service. Without one, open
the device; see docs/flash-access.md.
"""
        )
        if not in_docker():
            try:
                webbrowser.open("https://console.aws.amazon.com/cloudshell/home")
            except Exception:  # noqa: BLE001
                pass
        return 0

    if action == "login" and args.sso:
        return _sso_login(ctx, args)

    if action == "login":
        step(1, 2, "Enter AWS credentials")
        setup_code = args.setup_code
        if setup_code is None and not args.access_key:
            setup_code = getpass.getpass(
                "Setup code from CloudShell (or press Enter to type an access key): "
            ).strip()

        if setup_code and not setup_code.startswith(("AKIA", "ASIA")):
            data = aws.decode_setup_code(setup_code)
            access_key = data["access_key_id"]
            secret_key = data["secret_access_key"]
        else:
            access_key = args.access_key or setup_code or input("Access key ID: ").strip()
            if not access_key:
                raise CutterError("an access key ID is required")
            secret_key = args.secret_key or getpass.getpass("Secret access key: ")
            if not secret_key:
                raise CutterError("a secret access key is required")
        profile = args.profile or "default"
        region = args.region or aws.resolve_region(profile) or "eu-west-1"

        step(2, 2, "Validate with STS")
        ident = aws.validate_credentials(
            access_key=access_key,
            secret_key=secret_key,
            session_token=args.session_token or "",
            region=region,
        )
        path = aws.save_credentials(
            access_key=access_key,
            secret_key=secret_key,
            session_token=args.session_token or "",
            region=region,
            profile=profile,
        )
        ok(f"account {ident['Account']}  {ident['Arn']}")
        ok(f"saved {path}")
        if profile != "default":
            info(f"use it with --profile {profile} or export AWS_PROFILE={profile}")
        info("next: blueair-cloudcutter aws check")
        return 0

    if action == "onboard":
        if not args.device_cert:
            raise CutterError("onboard needs --device-cert (the captured c-b certificate)")
        step(1, 1, "Register the device and create a control identity")
        cfg = aws.onboard(
            output=ctx.output,
            device_cert=Path(args.device_cert),
            thing=args.thing,
            region=args.region,
            policy=args.policy,
            control_name=args.control_name,
            profile=args.profile,
        )
        print()
        print(aws.format_config(cfg))
        print()
        info("Next: `blueair-cloudcutter helpers ble provision --ssid ... --password ...`")
        info("The endpoint is loaded from output/aws.json automatically.")
        return 0

    if action == "show":
        _select(ctx, args)
        cfg = _load(ctx)
        print(aws.format_config(cfg))
        return 0

    if action == "discover":
        _select(ctx, args)
        cfg = _load(ctx)
        step(1, 1, "Listen for the device's first message to learn its DID")
        mqtt = MQTT(
            MQTTConfig(
                host=cfg.endpoint,
                port=8883,
                cert=Path(cfg.control_cert),
                key=Path(cfg.control_key),
            )
        )
        with mqtt:
            messages = mqtt.listen(
                "#",
                args.timeout,
                stop_when=lambda topic, payload: bool(extract_uuid(topic) or extract_uuid(payload)),
            )
        for topic, payload in messages:
            did = extract_uuid(topic) or extract_uuid(payload)
            if did:
                cfg.did = did
                cfg.save(aws.default_path(ctx.output))
                devices.upsert(ctx.output, cfg, did=did)
                ok(f"DID: {did}")
                info(f"saved to {aws.default_path(ctx.output)}")
                return 0
        raise CutterError(
            "no device message seen. Is the device connected to this AWS account, and "
            "has it booted since you registered its certificate?"
        )

    raise CutterError(f"unknown AWS action {action!r}")
