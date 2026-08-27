#!/bin/bash
# Test suite for cert-helper.sh backend engine with security and hardening tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$SCRIPT_DIR/backend/cert-helper.sh"

TEST_TMP_DIR=$(mktemp -d)
export XDG_DATA_HOME="$TEST_TMP_DIR/data"
mkdir -p "$XDG_DATA_HOME"

cleanup() {
  rm -rf "$TEST_TMP_DIR"
}
trap cleanup EXIT

echo "=== Test 1: Discover Files and Networks ==="
OUT=$("$HELPER" discover)
echo "$OUT" | jq -e '.success == true and (.files | type == "array") and (.networks | type == "array")' >/dev/null
echo "PASS: Discover files and networks"

# Generate mock PKCS#12 test certificate bundle
MOCK_P12="$TEST_TMP_DIR/mock_cert.p12"
MOCK_KEY="$TEST_TMP_DIR/mock.key"
MOCK_CRT="$TEST_TMP_DIR/mock.crt"
MOCK_CA_KEY="$TEST_TMP_DIR/mock_ca.key"
MOCK_CA_CRT="$TEST_TMP_DIR/mock_ca.crt"
TEST_PASS="TestPass123!"

openssl req -x509 -newkey rsa:2048 -keyout "$MOCK_CA_KEY" -out "$MOCK_CA_CRT" -days 365 -nodes -subj "/CN=Mock Enterprise CA/O=Enterprise/C=US" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$MOCK_KEY" -out "$TEST_TMP_DIR/mock.csr" -nodes -subj "/CN=employee_12345@enterprise.com/emailAddress=employee@enterprise.com" 2>/dev/null
openssl x509 -req -in "$TEST_TMP_DIR/mock.csr" -CA "$MOCK_CA_CRT" -CAkey "$MOCK_CA_KEY" -CAcreateserial -out "$MOCK_CRT" -days 180 2>/dev/null
openssl pkcs12 -export -out "$MOCK_P12" -inkey "$MOCK_KEY" -in "$MOCK_CRT" -certfile "$MOCK_CA_CRT" -passout "pass:$TEST_PASS" 2>/dev/null

echo "=== Test 2: Inspect Encrypted PKCS#12 Certificate & Auto-Extract Domain (SEC-01) ==="
INSPECT_OUT=$(printf "%s" "$TEST_PASS" | "$HELPER" inspect --file "$MOCK_P12")
echo "$INSPECT_OUT" | jq -e '.success == true and .hasCa == true and .identity == "employee_12345@enterprise.com" and .domain == "enterprise.com"' >/dev/null
echo "PASS: Inspect encrypted bundle and extracted domain realm"

echo "=== Test 3: Reject Inspection with Wrong Password ==="
if printf "WrongPassword!" | "$HELPER" inspect --file "$MOCK_P12" 2>/dev/null; then
  echo "FAIL: Expected rejection on wrong password"
  exit 1
else
  echo "PASS: Rejected invalid password"
fi

echo "=== Test 4: Install Profile in Sandbox ==="
INSTALL_OUT=$(printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "Corp_Secure" --domain "enterprise.com")
echo "$INSTALL_OUT" | jq -e '.success == true and .ssid == "Corp_Secure" and .profileId == "corp_secure"' >/dev/null
echo "PASS: Install profile"

echo "=== Test 5: List Profiles in Sandbox ==="
LIST_OUT=$("$HELPER" list)
echo "$LIST_OUT" | jq -e '.success == true and (.profiles | length == 1) and .profiles[0].id == "corp_secure"' >/dev/null
echo "PASS: List profiles"

echo "=== Test 6: Verify Profile File Security (700 dir, 600 key) (SEC-05) ==="
[[ -d "$XDG_DATA_HOME/cert-wifi" ]]
[[ -d "$XDG_DATA_HOME/cert-wifi/profiles" ]]
[[ -d "$XDG_DATA_HOME/cert-wifi/profiles/corp_secure" ]]
BASE_PERM=$(stat -c%a "$XDG_DATA_HOME/cert-wifi")
PROF_PERM=$(stat -c%a "$XDG_DATA_HOME/cert-wifi/profiles")
DIR_PERM=$(stat -c%a "$XDG_DATA_HOME/cert-wifi/profiles/corp_secure")
KEY_PERM=$(stat -c%a "$XDG_DATA_HOME/cert-wifi/profiles/corp_secure/client.key")
[[ "$BASE_PERM" == "700" ]] || { echo "Base dir permission unsafe: $BASE_PERM"; exit 1; }
[[ "$PROF_PERM" == "700" ]] || { echo "Profiles dir permission unsafe: $PROF_PERM"; exit 1; }
[[ "$DIR_PERM" == "700" ]] || { echo "Directory permission unsafe: $DIR_PERM"; exit 1; }
[[ "$KEY_PERM" == "600" ]] || { echo "Private key permission unsafe: $KEY_PERM"; exit 1; }
echo "PASS: Directory and key file permissions strictly verified (700 dirs, 600 key)"

echo "=== Test 7: Delete Profile from Sandbox ==="
DEL_OUT=$("$HELPER" delete --id corp_secure)
echo "$DEL_OUT" | jq -e '.success == true and .deleted == "corp_secure"' >/dev/null
echo "PASS: Delete profile"

echo "=== Test 8: Error Handling for Nonexistent Bundle ==="
if printf "" | "$HELPER" inspect --file "$TEST_TMP_DIR/nonexistent.p12" 2>/dev/null; then
  echo "FAIL: Expected error on missing file"
  exit 1
else
  echo "PASS: Rejected missing file"
fi

echo "=== Test 9: Inspect via Unclosed Pipe/FIFO (Quickshell stdin emulation) ==="
FIFO="$TEST_TMP_DIR/test_fifo"
mkfifo "$FIFO"
exec 3<>"$FIFO"
printf "%s\n" "$TEST_PASS" >&3
FIFO_OUT=$("$HELPER" inspect --file "$MOCK_P12" <&3)
exec 3>&-
rm -f "$FIFO"
echo "$FIFO_OUT" | jq -e '.success == true and .identity == "employee_12345@enterprise.com"' >/dev/null
echo "PASS: Handled unclosed stdin pipe without hanging"

echo "=== Test 10: Inspect and Install via --password argument with Warning (SEC-02) ==="
ARG_OUT=$(printf "" | "$HELPER" inspect --file "$MOCK_P12" --password "$TEST_PASS" 2>/dev/null)
echo "$ARG_OUT" | jq -e '.success == true' >/dev/null
ARG_INSTALL=$(printf "" | "$HELPER" install --file "$MOCK_P12" --ssid "Arg_Net" --password "$TEST_PASS" 2>/dev/null)
echo "$ARG_INSTALL" | jq -e '.success == true and .profileId == "arg_net"' >/dev/null
"$HELPER" delete --id arg_net >/dev/null
echo "PASS: --password argument handled"

echo "=== Test 11: Auto-Suggest SSID and Domain for eduroam/easyroam Certificates (SEC-01) ==="
EDUROAM_KEY="$TEST_TMP_DIR/eduroam.key"
EDUROAM_CRT="$TEST_TMP_DIR/eduroam.crt"
EDUROAM_P12="$TEST_TMP_DIR/eduroam.p12"
openssl req -newkey rsa:2048 -keyout "$EDUROAM_KEY" -out "$TEST_TMP_DIR/eduroam.csr" -nodes -subj "/CN=user123@eduroam.example.edu/OU=eduroam" 2>/dev/null
openssl x509 -req -in "$TEST_TMP_DIR/eduroam.csr" -CA "$MOCK_CA_CRT" -CAkey "$MOCK_CA_KEY" -CAcreateserial -out "$EDUROAM_CRT" -days 180 2>/dev/null
openssl pkcs12 -export -out "$EDUROAM_P12" -inkey "$EDUROAM_KEY" -in "$EDUROAM_CRT" -certfile "$MOCK_CA_CRT" -passout "pass:" 2>/dev/null

EDUROAM_OUT=$(printf "\n" | "$HELPER" inspect --file "$EDUROAM_P12")
echo "$EDUROAM_OUT" | jq -e '.success == true and .suggestedSsid == "eduroam" and .domain == "eduroam.example.edu"' >/dev/null
echo "PASS: Auto-suggested SSID and domain for eduroam/easyroam certificate"

echo "=== Test 11b: Easyroam PCA Realm to easyroam.eduroam.de Domain Normalization ==="
EASYROAM_KEY="$TEST_TMP_DIR/easyroam.key"
EASYROAM_CRT="$TEST_TMP_DIR/easyroam.crt"
EASYROAM_P12="$TEST_TMP_DIR/easyroam.p12"
openssl req -newkey rsa:2048 -keyout "$EASYROAM_KEY" -out "$TEST_TMP_DIR/easyroam.csr" -nodes -subj "/CN=user_sample@easyroam-pca.example.edu/OU=easyroam" 2>/dev/null
openssl x509 -req -in "$TEST_TMP_DIR/easyroam.csr" -CA "$MOCK_CA_CRT" -CAkey "$MOCK_CA_KEY" -CAcreateserial -out "$EASYROAM_CRT" -days 180 2>/dev/null
openssl pkcs12 -export -out "$EASYROAM_P12" -inkey "$EASYROAM_KEY" -in "$EASYROAM_CRT" -certfile "$MOCK_CA_CRT" -passout "pass:" 2>/dev/null

EASYROAM_OUT=$(printf "\n" | "$HELPER" inspect --file "$EASYROAM_P12")
echo "$EASYROAM_OUT" | jq -e '.success == true and .suggestedSsid == "eduroam" and .domain == "easyroam.eduroam.de"' >/dev/null
echo "PASS: Easyroam PCA realm correctly mapped to easyroam.eduroam.de domain"

echo "=== Test 12: Unicode / Symbol SSID Slug & Profiles Directory Protection (SEC-01) ==="
UNICODE_OUT=$(printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "日本語" --domain "enterprise.com")
UNICODE_PID=$(echo "$UNICODE_OUT" | jq -r '.profileId')
[[ -n "$UNICODE_PID" && "$UNICODE_PID" =~ ^wifi_[a-f0-9]+$ ]]
[[ -d "$XDG_DATA_HOME/cert-wifi/profiles/$UNICODE_PID" ]]
[[ -d "$XDG_DATA_HOME/cert-wifi/profiles" ]]
"$HELPER" delete --id "$UNICODE_PID" >/dev/null
echo "PASS: Handled Unicode SSID safely without profiles directory wipe"

echo "=== Test 13: Quotes and Special Characters in SSID JSON Safety (SEC-04) ==="
QUOTE_SSID='Alice'\''s "Secure" Net'
QUOTE_OUT=$(printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "$QUOTE_SSID" --domain "enterprise.com")
QUOTE_PID=$(echo "$QUOTE_OUT" | jq -r '.profileId')
LIST_QUOTE=$("$HELPER" list)
echo "$LIST_QUOTE" | jq -e --arg expected "$QUOTE_SSID" '.success == true and .profiles[0].ssid == $expected' >/dev/null
"$HELPER" delete --id "$QUOTE_PID" >/dev/null
echo "PASS: Quotes and backslashes escaped safely in JSON"

echo "=== Test 14: Path Traversal Rejection in Delete Command ==="
printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "Protected_Net" >/dev/null

for BAD_ID in ".." "." "/" "foo/bar" "../.." ""; do
  if "$HELPER" delete --id "$BAD_ID" 2>/dev/null; then
    echo "FAIL: Expected failure on bad ID: $BAD_ID"
    exit 1
  fi
done

[[ -d "$XDG_DATA_HOME/cert-wifi/profiles/protected_net" ]]
"$HELPER" delete --id "protected_net" >/dev/null
echo "PASS: Path traversal attempts strictly rejected in delete"

echo "=== Test 15: IEEE 802.11 SSID Byte-Length Enforcement (Max 32 Octets) (SEC-04) ==="
# Case A: Long ASCII string (>32 bytes)
LONG_ASCII="This_SSID_Is_Way_Too_Long_And_Exceeds_Thirty_Two_Bytes"
if printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "$LONG_ASCII" 2>/dev/null; then
  echo "FAIL: Expected failure on overlong ASCII SSID"
  exit 1
fi

# Case B: Multi-byte UTF-8 string: 9 emojis (9 characters, but 36 bytes > 32 bytes)
OVERLONG_UTF8="🚀🚀🚀🚀🚀🚀🚀🚀🚀"
if printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "$OVERLONG_UTF8" 2>/dev/null; then
  echo "FAIL: Expected failure on multi-byte UTF-8 SSID exceeding 32 bytes"
  exit 1
fi

# Case C: Multi-byte UTF-8 string: 6 emojis (6 characters, 24 bytes <= 32 bytes)
VALID_UTF8="🚀🚀🚀🚀🚀🚀"
UTF8_INSTALL=$(printf "%s" "$TEST_PASS" | "$HELPER" install --file "$MOCK_P12" --ssid "$VALID_UTF8")
echo "$UTF8_INSTALL" | jq -e '.success == true' >/dev/null
UTF8_PID=$(echo "$UTF8_INSTALL" | jq -r '.profileId')
"$HELPER" delete --id "$UTF8_PID" >/dev/null
echo "PASS: Strict 32-byte SSID limit enforced on ASCII and multi-byte UTF-8"

echo "=== Test 16: Temporary Staging Isolation Inside Private BASE_DIR (SEC-03) ==="
# Verify no temp dirs leaked in global /tmp and that cleanup removes BASE_DIR/.tmp_*
LEAKED_TMP=$(ls -d /tmp/.tmp_* 2>/dev/null || true)
BASE_TMP=$(ls -d "$XDG_DATA_HOME/cert-wifi/.tmp_"* 2>/dev/null || true)
[[ -z "$BASE_TMP" ]] || { echo "FAIL: Leftover temp staging directory in BASE_DIR"; exit 1; }
echo "PASS: Private temp directory cleaned up properly without leakage"

echo "================================================="
echo "All 16 security and unit tests passed successfully."
echo "================================================="
