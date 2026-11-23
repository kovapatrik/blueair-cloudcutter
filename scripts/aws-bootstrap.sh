#!/usr/bin/env bash
# Run this in AWS CloudShell (console.aws.amazon.com/cloudshell).
#
# It creates a dedicated IAM user for blueair-cloudcutter with the operator policy
# and prints one access key. There is no console login for the user, and the
# key cannot create users or touch anything outside the policy.
#
# Re-running is safe: the IAM user and policy are detected and reused, and an
# existing policy version is only replaced when the permissions changed. An
# existing access key is never replaced silently; pass --rotate if you lost the
# setup code and want a new key.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kovapatrik/blueair-cloudcutter/main/scripts/aws-bootstrap.sh | bash
#
# Or, from a clone:
#   bash scripts/aws-bootstrap.sh
#   bash scripts/aws-bootstrap.sh --rotate
set -euo pipefail

USER_NAME="${BLUEAIR_IAM_USER:-blueair-cloudcutter}"
POLICY_NAME="${BLUEAIR_POLICY_NAME:-BlueAirCloudCutterOperator}"
POLICY_FILE="$(mktemp)"
CURRENT_FILE="$(mktemp)"
trap 'rm -f "$POLICY_FILE" "$CURRENT_FILE"' EXIT

ROTATE=0
for arg in "$@"; do
  case "$arg" in
    --rotate) ROTATE=1 ;;
    -h|--help)
      echo "usage: $0 [--rotate]"
      echo
      echo "  --rotate   delete existing access keys and create a new one"
      echo "             (old setup codes stop working)"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      echo "usage: $0 [--rotate]" >&2
      exit 2
      ;;
  esac
done

into_account() {
  aws sts get-caller-identity --query Account --output text
}

ACCOUNT="$(into_account)"
POLICY_ARN="arn:aws:iam::${ACCOUNT}:policy/${POLICY_NAME}"

cat > "$POLICY_FILE" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Iot",
      "Effect": "Allow",
      "Action": [
        "iot:DescribeEndpoint",
        "iot:CreatePolicy",
        "iot:GetPolicy",
        "iot:CreateThing",
        "iot:DescribeThing",
        "iot:AttachPolicy",
        "iot:AttachThingPrincipal",
        "iot:RegisterCertificateWithoutCA",
        "iot:DescribeCertificate",
        "iot:UpdateCertificate",
        "iot:CreateKeysAndCertificate"
      ],
      "Resource": "*"
    }
  ]
}
JSON

policy_is_current() {
  aws iam get-policy-version \
    --policy-arn "$POLICY_ARN" \
    --version-id "$DEFAULT_VERSION" \
    --output json > "$CURRENT_FILE" 2>/dev/null || return 1
  python3 - "$POLICY_FILE" "$CURRENT_FILE" <<'PY'
import json
import sys
import urllib.parse

desired = json.load(open(sys.argv[1]))
current = json.load(open(sys.argv[2]))["PolicyVersion"]["Document"]
if isinstance(current, str):
    current = json.loads(urllib.parse.unquote(current))
raise SystemExit(0 if current == desired else 1)
PY
}

if aws iam get-policy --policy-name "$POLICY_NAME" >/dev/null 2>&1; then
  POLICY_ARN="$(aws iam get-policy --policy-name "$POLICY_NAME" --query 'Policy.Arn' --output text)"
  DEFAULT_VERSION="$(aws iam get-policy --policy-name "$POLICY_NAME" \
    --query 'Policy.DefaultVersionId' --output text)"
  if policy_is_current; then
    echo "[=] policy ${POLICY_NAME} already up to date"
  else
    echo "[*] updating policy ${POLICY_NAME}"
    if ! aws iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document "file://${POLICY_FILE}" \
        --set-as-default >/dev/null 2>&1; then
      OLD_VERSION="$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`] | [0].VersionId' --output text)"
      if [ -z "$OLD_VERSION" ] || [ "$OLD_VERSION" = "None" ]; then
        echo "[-] cannot create a new policy version; delete an old one first" >&2
        exit 1
      fi
      aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLD_VERSION"
      aws iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document "file://${POLICY_FILE}" --set-as-default >/dev/null
    fi
  fi
else
  POLICY_ARN="$(aws iam create-policy --policy-name "$POLICY_NAME" \
    --policy-document "file://${POLICY_FILE}" --query 'Policy.Arn' --output text)"
  echo "[+] created policy ${POLICY_NAME}"
fi

if aws iam get-user --user-name "$USER_NAME" >/dev/null 2>&1; then
  echo "[=] IAM user ${USER_NAME} already exists"
else
  aws iam create-user --user-name "$USER_NAME" >/dev/null
  echo "[+] created IAM user ${USER_NAME}"
fi
aws iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$POLICY_ARN"

KEY_IDS="$(aws iam list-access-keys --user-name "$USER_NAME" \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
KEY_COUNT=0
if [ -n "$KEY_IDS" ]; then
  KEY_COUNT="$(printf '%s\n' $KEY_IDS | wc -w | tr -d ' ')"
fi

if [ "$KEY_COUNT" -gt 0 ] && [ "$ROTATE" -ne 1 ]; then
  echo "[=] IAM user ${USER_NAME} already has access key(s): ${KEY_IDS}"
  echo "    No new key was created."
  echo "    If you lost the setup code, rerun with --rotate to replace it."
  echo
  echo "    Account:   ${ACCOUNT}"
  echo "    IAM user:  ${USER_NAME}"
  echo "    Policy:    ${POLICY_NAME}"
  exit 0
fi

if [ "$ROTATE" -eq 1 ] && [ "$KEY_COUNT" -gt 0 ]; then
  for key in $KEY_IDS; do
    echo "[*] deleting access key ${key}"
    aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$key"
  done
fi

KEY_JSON="$(aws iam create-access-key --user-name "$USER_NAME")"
ACCESS_KEY="$(printf '%s' "$KEY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKey"]["AccessKeyId"])')"
SECRET_KEY="$(printf '%s' "$KEY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKey"]["SecretAccessKey"])')"

SETUP_CODE="$(python3 - "${ACCESS_KEY}" "${SECRET_KEY}" <<'PY'
import base64, json, sys

payload = {"v": 1, "access_key_id": sys.argv[1], "secret_access_key": sys.argv[2]}
raw = json.dumps(payload, separators=(",", ":")).encode()
print(base64.urlsafe_b64encode(raw).decode().rstrip("="))
PY
)"

cat <<EOF

[+] done. Copy this one-line setup code into \`blueair-cloudcutter aws login\` on the Pi:

${SETUP_CODE}

    Account:   ${ACCOUNT}
    IAM user:  ${USER_NAME}
    Policy:    ${POLICY_NAME}

Treat the code like a password: it contains the access key. It can create IoT
things and certificates in this account. Delete the IAM user when you are done.
EOF
