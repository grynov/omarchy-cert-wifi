#!/bin/bash
# 802.1X EAP-TLS certificate Wi-Fi backend engine for Omarchy.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FD_HELPER="$SCRIPT_DIR/fd-helper.py"

if ! command -v jq >/dev/null 2>&1; then
  echo '{"success":false,"error":"Missing required dependency: jq"}' >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo '{"success":false,"error":"Missing required dependency: openssl"}' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo '{"success":false,"error":"Missing required dependency: python3"}' >&2
  exit 1
fi

# Global Resource & Security Limits
MAX_CERT_FILE_SIZE=$((10 * 1024 * 1024))   # 10 MB maximum for certificate bundles
MAX_PROFILE_JSON_SIZE=$((64 * 1024))       # 64 KB maximum for profile.json
MAX_CERT_CRT_SIZE=$((1 * 1024 * 1024))     # 1 MB maximum for .crt files
MAX_DISCOVER_SCAN_PER_DIR=100              # Maximum find results scanned per directory
MAX_DISCOVER_FILES=50                      # Maximum certificate files returned in discover
MAX_DISCOVER_NETWORKS=30                   # Maximum Wi-Fi networks returned in discover
MAX_PROFILES_COUNT=50                      # Maximum profile directories processed in list
MAX_AGGREGATE_OUTPUT_SIZE=$((512 * 1024))  # 512 KB maximum stdout payload

BASE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/cert-wifi"
PROFILES_DIR="$BASE_DIR/profiles"
mkdir -p "$PROFILES_DIR"
chmod 700 "$BASE_DIR" "$PROFILES_DIR" 2>/dev/null || true

TMP_DIR=""
cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
    # Overwrite and shred sensitive decrypted private keys and staged bundles before directory removal
    find "$TMP_DIR" -type f \( -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) -exec shred -u {} + 2>/dev/null || true
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT HUP INT QUIT TERM

die() {
  local msg="$1"
  jq -c -n --arg error "$msg" '{success: false, error: $error}' >&2
  exit 1
}

# Safely read and validate profile.json using descriptor helper (O_NOFOLLOW|O_NONBLOCK, fstat, bounded read)
read_safe_profile_json() {
  local pdir="$1"
  local json_file="$pdir/profile.json"
  local content
  if content=$("$FD_HELPER" read "$json_file" "$MAX_PROFILE_JSON_SIZE" 2>/dev/null); then
    if [[ -n "$content" ]] && jq -e . <<< "$content" >/dev/null 2>&1; then
      printf '%s' "$content"
      return 0
    fi
  fi
  return 1
}

# Safely emit JSON to stdout with aggregate size ceiling enforcement
safe_emit_json() {
  local out="$1"
  local len
  len=$(LC_ALL=C printf '%s' "$out" | wc -c)
  if (( len > MAX_AGGREGATE_OUTPUT_SIZE )); then
    die "Output exceeds maximum aggregate response size limit (${len} bytes > ${MAX_AGGREGATE_OUTPUT_SIZE} bytes)."
  fi
  printf '%s\n' "$out"
}

# Safely generate a profile ID from SSID preventing slug collapse, traversal, or empty values
sanitize_profile_id() {
  local input="$1"
  local slug
  slug=$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9_-' '_' | sed -E 's/^_+|_+$//g')
  if [[ -z "$slug" ]]; then
    slug="wifi_$(printf '%s' "$input" | sha256sum 2>/dev/null | cut -c1-12)"
  fi
  if [[ -z "$slug" || "$slug" == "." || "$slug" == ".." || "$slug" =~ [/] ]]; then
    slug="wifi_$(date +%s%N 2>/dev/null | cut -c1-12 || echo "default")"
  fi
  echo "$slug"
}

# Validate profile ID before any filesystem operations
validate_profile_id() {
  local id="$1"
  [[ -n "$id" ]] || die "Profile ID cannot be empty."
  [[ "$id" != "." && "$id" != ".." ]] || die "Invalid profile ID: $id"
  [[ ! "$id" =~ [/] ]] || die "Profile ID cannot contain slashes: $id"
  [[ "$id" =~ ^[a-z0-9_-]+$ ]] || die "Profile ID contains invalid characters: $id"
}

# Dynamically determine wireless interface for iwd/iwctl
get_wlan_iface() {
  local iface=""
  if command -v iwctl >/dev/null 2>&1; then
    iface=$(iwctl device list 2>/dev/null | awk '/station/ {print $2; exit}' || echo "")
  fi
  if [[ -z "$iface" ]]; then
    iface=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^wl/ {print $2; exit}' || echo "")
  fi
  echo "${iface:-wlan0}"
}

# Safely format iwd profile path per iwd.network(5) specifications
get_iwd_profile_path() {
  local ssid_input="$1"
  if [[ "$ssid_input" =~ ^[a-zA-Z0-9_.-]+$ && "$ssid_input" != "." && "$ssid_input" != ".." ]]; then
    echo "/var/lib/iwd/${ssid_input}.8021x"
  else
    local hex_ssid
    hex_ssid=$(LC_ALL=C printf '%s' "$ssid_input" | od -An -tx1 | tr -d ' \n')
    echo "/var/lib/iwd/=${hex_ssid}.8021x"
  fi
}

# Dynamically detect if OpenSSL needs -legacy to decrypt PKCS12 bundles (consumed from staged private file)
detect_pkcs12_flag() {
  local file="$1"
  local pass="$2"
  
  if openssl pkcs12 -in "$file" -passin stdin -info -noout <<< "$pass" >/dev/null 2>&1; then
    echo ""
  elif openssl pkcs12 -in "$file" -legacy -passin stdin -info -noout <<< "$pass" >/dev/null 2>&1; then
    echo "-legacy"
  else
    echo "INVALID"
  fi
}

cmd_discover() {
  # 1. Discover certificate files (including localized XDG directories)
  local search_dirs=()
  local xdg_dl xdg_doc
  xdg_dl=$(xdg-user-dir DOWNLOAD 2>/dev/null || echo "$HOME/Downloads")
  xdg_doc=$(xdg-user-dir DOCUMENTS 2>/dev/null || echo "$HOME/Documents")
  [[ -d "$xdg_dl" ]]           && search_dirs+=("$xdg_dl")
  [[ -d "$xdg_doc" ]]          && search_dirs+=("$xdg_doc")
  [[ -d "$HOME/Downloads" ]]   && search_dirs+=("$HOME/Downloads")
  [[ -d "$HOME/Projects" ]]    && search_dirs+=("$HOME/Projects")
  [[ -d "$HOME/Documents" ]]   && search_dirs+=("$HOME/Documents")
  [[ -d "$HOME" ]]             && search_dirs+=("$HOME")

  local raw_candidates=()
  for dir in "${search_dirs[@]}"; do
    local max_d=2
    [[ "$dir" == "$HOME" ]] && max_d=1
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      raw_candidates+=("$f")
    done < <(find "$dir" -maxdepth "$max_d" -type f \( -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | head -n "$MAX_DISCOVER_SCAN_PER_DIR")
  done

  local file_results="[]"
  if (( ${#raw_candidates[@]} > 0 )); then
    local candidates_json
    candidates_json=$(printf '%s\n' "${raw_candidates[@]}" | sort -u | jq -R . | jq -s .)
    file_results=$(printf '%s' "$candidates_json" | "$FD_HELPER" discover "$MAX_CERT_FILE_SIZE" "$MAX_DISCOVER_FILES" 2>/dev/null || echo "[]")
  fi

  # 2. Discover visible Wi-Fi networks
  local net_items=()
  if command -v nmcli >/dev/null 2>&1; then
    while IFS=: read -r s_ssid s_sec s_sig; do
      [[ -n "$s_ssid" ]] || continue
      net_items+=("$(jq -c -n --arg ssid "$s_ssid" --arg sec "$s_sec" --arg sig "$s_sig" \
        '{ssid: $ssid, security: $sec, signal: ($sig|tonumber? // 0)}')")
      if (( ${#net_items[@]} >= MAX_DISCOVER_NETWORKS )); then
        break
      fi
    done < <(nmcli -t -f SSID,SECURITY,SIGNAL dev wifi 2>/dev/null | head -n "$MAX_DISCOVER_NETWORKS" || true)
  fi

  local net_results="[]"
  if (( ${#net_items[@]} > 0 )); then
    net_results=$(printf '%s\n' "${net_items[@]}" | jq -c -s 'unique_by(.ssid)')
  fi

  local out
  out=$(jq -c -n \
    --argjson files "$file_results" \
    --argjson networks "$net_results" \
    '{success: true, files: $files, networks: $networks}')
  safe_emit_json "$out"
}

cmd_inspect() {
  local file=""
  local pass=""
  local pass_given=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file)     file="$2"; shift 2 ;;
      --password)
        pass="$2"
        pass_given=true
        echo '{"warning":"Passing passwords via CLI flags exposes credentials in the process table. Use stdin instead."}' >&2
        shift 2
        ;;
      *) shift ;;
    esac
  done

  [[ -n "$file" ]] || die "File not provided."
  file="${file/#\~/$HOME}"

  if [[ "$pass_given" != "true" ]] && ! [ -t 0 ]; then
    IFS= read -t 1 -r pass || true
  fi

  TMP_DIR=$(mktemp -d -p "$BASE_DIR" .tmp_XXXXXX)
  chmod 700 "$TMP_DIR"
  local staged_bundle="$TMP_DIR/staged.p12"

  # Descriptor-based safe copy: opens once with O_NOFOLLOW|O_NONBLOCK, validates owner/type/size, reads cap+1
  "$FD_HELPER" stage "$file" "$staged_bundle" "$MAX_CERT_FILE_SIZE" || die "File not found, not a regular file owned by current user, or exceeds maximum allowable size (10 MB): $file"

  local flag
  flag=$(detect_pkcs12_flag "$staged_bundle" "$pass")
  [[ "$flag" != "INVALID" ]] || die "Cannot decrypt PKCS#12 file (invalid password or corrupted certificate bundle)."

  local leaf_cert="$TMP_DIR/leaf.crt"
  local ca_cert="$TMP_DIR/ca.crt"

  if [[ -n "$flag" ]]; then
    openssl pkcs12 -in "$staged_bundle" -legacy -passin stdin -nodes -clcerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$leaf_cert" || true
    openssl pkcs12 -in "$staged_bundle" -legacy -passin stdin -nodes -cacerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$ca_cert" || true
  else
    openssl pkcs12 -in "$staged_bundle" -passin stdin -nodes -clcerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$leaf_cert" || true
    openssl pkcs12 -in "$staged_bundle" -passin stdin -nodes -cacerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$ca_cert" || true
  fi

  [[ -s "$leaf_cert" ]] || die "No client certificate found in bundle."

  local subject issuer not_before not_after identity domain suggested_ssid
  subject=$(openssl x509 -noout -subject -in "$leaf_cert" 2>/dev/null || echo "")
  issuer=$(openssl x509 -noout -issuer -in "$leaf_cert" 2>/dev/null || echo "")
  not_before=$(openssl x509 -noout -startdate -in "$leaf_cert" 2>/dev/null | cut -d= -f2 || echo "")
  not_after=$(openssl x509 -noout -enddate -in "$leaf_cert" 2>/dev/null | cut -d= -f2 || echo "")
  
  identity=$(openssl x509 -noout -subject -in "$leaf_cert" 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+' || echo "")
  if [[ -z "$identity" ]]; then
    identity=$(openssl x509 -noout -ext subjectAltName -in "$leaf_cert" 2>/dev/null | grep -oP 'email:\s*\K[^,\s]+' | head -n 1 || echo "")
  fi
  if [[ -z "$identity" ]]; then
    identity=$(openssl x509 -noout -email -in "$leaf_cert" 2>/dev/null | head -n 1 || echo "")
  fi
  
  # Suggested SSID for well-known networks (optional UI convenience)
  suggested_ssid=""
  if [[ "$issuer" =~ (eduroam|geteduroam|easyroam) || "$subject" =~ (eduroam|geteduroam|easyroam) || "$identity" =~ (eduroam|easyroam) ]]; then
    suggested_ssid="eduroam"
  fi

  # Auto-extract realm domain suffix for MitM server certificate validation
  domain=""
  if [[ "$issuer" =~ (easyroam|geteduroam) || "$subject" =~ easyroam || "$identity" =~ easyroam ]]; then
    domain="easyroam.eduroam.de"
  elif [[ "$identity" =~ @([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) ]]; then
    local extracted_realm="${BASH_REMATCH[1]}"
    if [[ "$extracted_realm" =~ ^easyroam-pca\. || "$extracted_realm" =~ easyroam ]]; then
      domain="easyroam.eduroam.de"
    else
      domain="$extracted_realm"
    fi
  fi
  if [[ -z "$domain" ]]; then
    local san_domain
    san_domain=$(openssl x509 -noout -ext subjectAltName -in "$leaf_cert" 2>/dev/null | grep -oP 'DNS:\s*\K[^,\s]+' | head -n 1 || echo "")
    if [[ -n "$san_domain" ]]; then
      domain="$san_domain"
    fi
  fi
  if [[ -z "$domain" ]]; then
    local email_domain
    email_domain=$(openssl x509 -noout -email -in "$leaf_cert" 2>/dev/null | head -n 1 | grep -oP '@\K[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' || echo "")
    if [[ -n "$email_domain" ]]; then
      domain="$email_domain"
    fi
  fi

  local end_epoch now_epoch days_remaining
  end_epoch=$(LC_ALL=C date -d "$not_after" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_remaining=$(( (end_epoch - now_epoch) / 86400 ))

  local has_ca=false
  [[ -s "$ca_cert" ]] && has_ca=true

  local out
  out=$(jq -c -n \
    --arg path "$file" \
    --arg subject "$subject" \
    --arg issuer "$issuer" \
    --arg identity "$identity" \
    --arg domain "$domain" \
    --arg suggestedSsid "$suggested_ssid" \
    --arg notBefore "$not_before" \
    --arg notAfter "$not_after" \
    --argjson daysRemaining "$days_remaining" \
    --argjson hasCa "$has_ca" \
    '{
      success: true,
      file: $path,
      subject: $subject,
      issuer: $issuer,
      identity: $identity,
      domain: $domain,
      suggestedSsid: $suggestedSsid,
      notBefore: $notBefore,
      notAfter: $notAfter,
      daysRemaining: $daysRemaining,
      isExpired: ($daysRemaining <= 0),
      hasCa: $hasCa
    }')
  safe_emit_json "$out"
}

cmd_install() {
  local file=""
  local ssid=""
  local preset="generic"
  local domain=""
  local backend="auto"
  local identity=""
  local anonymous_identity=""

  local pass=""
  local pass_given=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file)               file="$2"; shift 2 ;;
      --ssid)               ssid="$2"; shift 2 ;;
      --preset)             preset="$2"; shift 2 ;;
      --domain)             domain="$2"; shift 2 ;;
      --backend)            backend="$2"; shift 2 ;;
      --identity)           identity="$2"; shift 2 ;;
      --anonymous-identity) anonymous_identity="$2"; shift 2 ;;
      --password)
        pass="$2"
        pass_given=true
        echo '{"warning":"Passing passwords via CLI flags exposes credentials in the process table. Use stdin instead."}' >&2
        shift 2
        ;;
      *) shift ;;
    esac
  done

  [[ -n "$file" ]] || die "Certificate file not provided."
  file="${file/#\~/$HOME}"
  [[ -n "$ssid" ]] || die "SSID cannot be empty."

  local ssid_bytes
  ssid_bytes=$(LC_ALL=C printf '%s' "$ssid" | wc -c)
  (( ssid_bytes <= 32 )) || die "SSID exceeds maximum length of 32 bytes ($ssid_bytes bytes provided)."

  if [[ "$pass_given" != "true" ]] && ! [ -t 0 ]; then
    IFS= read -t 1 -r pass || true
  fi

  TMP_DIR=$(mktemp -d -p "$BASE_DIR" .tmp_XXXXXX)
  chmod 700 "$TMP_DIR"
  local staged_bundle="$TMP_DIR/staged.p12"

  # Descriptor-based safe copy: opens once with O_NOFOLLOW|O_NONBLOCK, validates owner/type/size, reads cap+1
  "$FD_HELPER" stage "$file" "$staged_bundle" "$MAX_CERT_FILE_SIZE" || die "Certificate file not found, not a regular file owned by current user, or exceeds maximum allowable size (10 MB): $file"

  local flag
  flag=$(detect_pkcs12_flag "$staged_bundle" "$pass")
  [[ "$flag" != "INVALID" ]] || die "Cannot decrypt PKCS#12 bundle. Check your password."

  # Generate clean profile slug based on SSID with deterministic fallback
  local profile_id
  profile_id=$(sanitize_profile_id "$ssid")
  validate_profile_id "$profile_id"
  local profile_dir="$PROFILES_DIR/$profile_id"

  # Guard: ensure profile_dir is strictly a subdirectory of PROFILES_DIR
  [[ "$profile_dir" == "$PROFILES_DIR/$profile_id" && "$profile_id" != "" ]] || die "Invalid profile directory resolution."

  local client_cert="$TMP_DIR/client.crt"
  local ca_cert="$TMP_DIR/ca.crt"
  local client_key="$TMP_DIR/client.key"

  if [[ -n "$flag" ]]; then
    openssl pkcs12 -in "$staged_bundle" -legacy -passin stdin -nodes -clcerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$client_cert" || true
    openssl pkcs12 -in "$staged_bundle" -legacy -passin stdin -nodes -cacerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$ca_cert" || true
    openssl pkcs12 -in "$staged_bundle" -legacy -passin stdin -nodes -nocerts <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$client_key" || true
  else
    openssl pkcs12 -in "$staged_bundle" -passin stdin -nodes -clcerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$client_cert" || true
    openssl pkcs12 -in "$staged_bundle" -passin stdin -nodes -cacerts -nokeys <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$ca_cert" || true
    openssl pkcs12 -in "$staged_bundle" -passin stdin -nodes -nocerts <<< "$pass" 2>/dev/null \
      | sed -n '/-----BEGIN/,/-----END/p' > "$client_key" || true
  fi

  [[ -s "$client_cert" ]] || die "Failed to extract client certificate from bundle."
  [[ -s "$client_key" ]]  || die "Failed to extract private key from bundle."

  # Verify key/cert match
  local cert_pub key_pub
  cert_pub=$(openssl x509 -noout -pubkey -in "$client_cert" 2>/dev/null)
  key_pub=$(openssl pkey -pubout -in "$client_key" 2>/dev/null)
  [[ "$cert_pub" == "$key_pub" ]] || die "Certificate and private key do not match!"

  # Extract identity if not provided
  if [[ -z "$identity" ]]; then
    identity=$(openssl x509 -noout -subject -in "$client_cert" 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+' || echo "")
  fi
  if [[ -z "$identity" ]]; then
    identity=$(openssl x509 -noout -ext subjectAltName -in "$client_cert" 2>/dev/null | grep -oP 'email:\s*\K[^,\s]+' | head -n 1 || echo "")
  fi
  if [[ -z "$identity" ]]; then
    identity=$(openssl x509 -noout -email -in "$client_cert" 2>/dev/null | head -n 1 || echo "")
  fi
  [[ -n "$identity" ]] || die "Could not determine identity from certificate."

  local not_before not_after end_epoch now_epoch days_remaining
  not_before=$(openssl x509 -noout -startdate -in "$client_cert" 2>/dev/null | cut -d= -f2 || echo "")
  not_after=$(openssl x509 -noout -enddate -in "$client_cert" 2>/dev/null | cut -d= -f2 || echo "")
  end_epoch=$(LC_ALL=C date -d "$not_after" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_remaining=$(( (end_epoch - now_epoch) / 86400 ))

  # Detect active backend
  local target_backend="$backend"
  if [[ "$target_backend" == "auto" ]]; then
    if command -v nmcli >/dev/null 2>&1 && (systemctl is-active --quiet NetworkManager 2>/dev/null || nmcli general status >/dev/null 2>&1); then
      target_backend="networkmanager"
    elif command -v iwctl >/dev/null 2>&1; then
      target_backend="iwd"
    else
      target_backend="networkmanager"
    fi
  fi

  # Store securely in profile directory
  rm -rf "$profile_dir"
  mkdir -p "$profile_dir"
  chmod 700 "$profile_dir"

  cp "$client_cert" "$profile_dir/client.crt"
  chmod 644 "$profile_dir/client.crt"

  cp "$client_key" "$profile_dir/client.key"
  chmod 600 "$profile_dir/client.key"

  local has_ca=false
  if [[ -s "$ca_cert" ]]; then
    cp "$ca_cert" "$profile_dir/ca.crt"
    chmod 644 "$profile_dir/ca.crt"
    has_ca=true
  fi

  # Save profile metadata JSON safely using jq (prevents JSON injection)
  jq -n \
    --arg id "$profile_id" \
    --arg ssid "$ssid" \
    --arg preset "$preset" \
    --arg identity "$identity" \
    --arg anonymousIdentity "$anonymous_identity" \
    --arg domain "$domain" \
    --arg backend "$target_backend" \
    --arg notBefore "$not_before" \
    --arg notAfter "$not_after" \
    --argjson daysRemaining "$days_remaining" \
    --argjson hasCa "$has_ca" \
    --arg installedAt "$(date -Iseconds)" \
    '{
      id: $id,
      ssid: $ssid,
      preset: $preset,
      identity: $identity,
      anonymousIdentity: $anonymousIdentity,
      domain: $domain,
      backend: $backend,
      notBefore: $notBefore,
      notAfter: $notAfter,
      daysRemaining: $daysRemaining,
      hasCa: $hasCa,
      installedAt: $installedAt
    }' > "$profile_dir/profile.json"
  chmod 600 "$profile_dir/profile.json"

  # Configure Network
  if [[ "$target_backend" == "networkmanager" ]]; then
    # Clean up any existing connection with this SSID to avoid duplicates
    nmcli connection delete id "$ssid" >/dev/null 2>&1 || nmcli connection delete "$ssid" >/dev/null 2>&1 || true

    # Detect easyroam: client cert issued by DFN-Verein/geteduroam, served via easyroam infrastructure.
    # For easyroam EAP-TLS: no anonymous-identity (RADIUS routes on cert CN), and the RADIUS server
    # cert chain (Sectigo) differs from the bundled Comodo CA, so use system trust store instead.
    local is_easyroam=false
    local client_issuer
    client_issuer=$(openssl x509 -noout -issuer -in "$profile_dir/client.crt" 2>/dev/null || echo "")
    if [[ "$client_issuer" =~ (easyroam|geteduroam|DFN-Verein) || "$domain" =~ easyroam ]]; then
      is_easyroam=true
    fi

    local nm_args=(
      connection add
      type wifi
      con-name "$ssid"
      ssid "$ssid"
      wifi-sec.key-mgmt wpa-eap
      802-1x.eap tls
      802-1x.identity "$identity"
      802-1x.client-cert "$profile_dir/client.crt"
      802-1x.private-key "$profile_dir/client.key"
      802-1x.private-key-password-flags 4
      802-1x.client-cert-password-flags 4
      802-1x.ca-cert-password-flags 4
    )

    # For EAP-TLS the client cert already carries the identity; anonymous-identity is only
    # appropriate for PEAP/TTLS outer tunnels. Skip it for easyroam to avoid RADIUS routing failures.
    if [[ -n "$anonymous_identity" && "$is_easyroam" == "false" ]]; then
      nm_args+=(802-1x.anonymous-identity "$anonymous_identity")
    fi

    if [[ "$is_easyroam" == "true" ]]; then
      # easyroam RADIUS server cert is signed by Sectigo, not the Comodo root in the bundle.
      # Use the system trust store so wpa_supplicant can verify the full server cert chain.
      nm_args+=(802-1x.system-ca-certs yes)
    elif [[ "$has_ca" == "true" ]]; then
      nm_args+=(802-1x.ca-cert "$profile_dir/ca.crt")
    else
      nm_args+=(802-1x.system-ca-certs yes)
    fi

    if [[ -n "$domain" ]]; then
      if [[ "$domain" =~ ^easyroam-pca\. || "$domain" =~ easyroam ]]; then
        domain="easyroam.eduroam.de"
      fi
      # Strip leading wildcard for NetworkManager domain-suffix-match
      local nm_domain="$domain"
      nm_domain="${nm_domain#\*.}"
      nm_args+=(802-1x.domain-suffix-match "$nm_domain")
    fi

    nmcli "${nm_args[@]}" >/dev/null || die "NetworkManager failed to add 802.1X profile."

    # Trigger connection attempt with short timeout (best effort)
    nmcli --wait 4 connection up id "$ssid" >/dev/null 2>&1 || nmcli --wait 4 connection up "$ssid" >/dev/null 2>&1 || true

  elif [[ "$target_backend" == "iwd" ]]; then
    local iwd_profile
    iwd_profile=$(get_iwd_profile_path "$ssid")

    # Strip newlines and carriage returns to prevent INI directive injection
    local clean_identity="${identity//$'\r'/}"
    clean_identity="${clean_identity//$'\n'/}"
    local clean_anon="${anonymous_identity//$'\r'/}"
    clean_anon="${clean_anon//$'\n'/}"
    local clean_domain="${domain//$'\r'/}"
    clean_domain="${clean_domain//$'\n'/}"
    if [[ "$clean_domain" =~ ^easyroam-pca\. || "$clean_domain" =~ easyroam ]]; then
      clean_domain="easyroam.eduroam.de"
    fi

    local iwd_conf="[Security]
EAP-Method=TLS
EAP-Identity=${clean_identity}
"
    if [[ -n "$clean_anon" ]]; then
      iwd_conf+="EAP-Anonymous-Identity=${clean_anon}
"
    fi
    if [[ "$has_ca" == "true" ]]; then
      iwd_conf+="EAP-TLS-CACert=${profile_dir}/ca.crt
"
    fi
    iwd_conf+="EAP-TLS-ClientCert=${profile_dir}/client.crt
EAP-TLS-ClientKey=${profile_dir}/client.key
"
    if [[ -n "$clean_domain" ]]; then
      local iwd_domain="$clean_domain"
      if [[ "$iwd_domain" != \** ]]; then
        iwd_conf+="EAP-TLS-ServerDomainMask=${iwd_domain};*.${iwd_domain}
"
      else
        iwd_conf+="EAP-TLS-ServerDomainMask=${iwd_domain}
"
      fi
    fi
    iwd_conf+="
[Settings]
AutoConnect=true
"

    if [[ $EUID -eq 0 ]]; then
      printf "%s" "$iwd_conf" > "$iwd_profile"
      chmod 600 -- "$iwd_profile"
    elif command -v pkexec >/dev/null 2>&1; then
      printf "%s" "$iwd_conf" | pkexec tee -- "$iwd_profile" >/dev/null
      pkexec chmod 600 -- "$iwd_profile"
    fi
  fi

  local out
  out=$(jq -c -n \
    --arg id "$profile_id" \
    --arg ssid "$ssid" \
    --arg identity "$identity" \
    --arg domain "$domain" \
    --arg backend "$target_backend" \
    --arg notAfter "$not_after" \
    --argjson daysRemaining "$days_remaining" \
    '{
      success: true,
      profileId: $id,
      ssid: $ssid,
      identity: $identity,
      domain: $domain,
      backend: $backend,
      notAfter: $notAfter,
      daysRemaining: $daysRemaining
    }')
  safe_emit_json "$out"
}

cmd_list() {
  local active_ssid=""
  if command -v nmcli >/dev/null 2>&1; then
    active_ssid=$(nmcli -t -f TYPE,STATE,CONNECTION dev 2>/dev/null | grep '^wifi:connected:' | head -n 1 | cut -d: -f3- || echo "")
    if [[ -z "$active_ssid" ]]; then
      active_ssid=$(nmcli -t -f ACTIVE,SSID dev wifi 2>/dev/null | grep '^yes:' | head -n 1 | cut -d: -f2- || echo "")
    fi
  elif command -v iwctl >/dev/null 2>&1; then
    local wlan_dev
    wlan_dev=$(get_wlan_iface)
    active_ssid=$(iwctl station "$wlan_dev" show 2>/dev/null | grep -i 'Connected network' | awk -F': ' '{print $2}' | xargs || echo "")
    if [[ -z "$active_ssid" ]]; then
      active_ssid=$(iwctl station list 2>/dev/null | grep -i 'connected' | head -n 1 | awk '{print $NF}' || echo "")
    fi
  fi

  local profile_items=()
  local count=0

  for pdir in "$PROFILES_DIR"/*; do
    [[ -d "$pdir" ]] || continue
    (( count < MAX_PROFILES_COUNT )) || break

    local pid
    pid=$(basename "$pdir")
    [[ "$pid" =~ ^[a-z0-9_-]+$ ]] || continue

    local pjson
    if ! pjson=$(read_safe_profile_json "$pdir"); then
      continue
    fi

    local client_cert="$pdir/client.crt"
    local not_after="" end_epoch=0 now_epoch=0 days_remaining=0
    local crt_bytes
    if crt_bytes=$("$FD_HELPER" read "$client_cert" "$MAX_CERT_CRT_SIZE" 2>/dev/null); then
      not_after=$(printf '%s' "$crt_bytes" | openssl x509 -noout -enddate -in /dev/stdin 2>/dev/null | cut -d= -f2 || echo "")
      if [[ -n "$not_after" ]]; then
        end_epoch=$(LC_ALL=C date -d "$not_after" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        days_remaining=$(( (end_epoch - now_epoch) / 86400 ))
      fi
    fi

    local p_ssid
    p_ssid=$(jq -r '.ssid // ""' <<< "$pjson" 2>/dev/null || echo "")
    local is_connected=false
    if [[ -n "$active_ssid" && "$active_ssid" == "$p_ssid" ]]; then
      is_connected=true
    fi

    local updated
    updated=$(jq -c \
      --argjson daysRemaining "$days_remaining" \
      --argjson isConnected "$is_connected" \
      --arg notAfter "$not_after" \
      '.daysRemaining = $daysRemaining | .isExpired = ($daysRemaining <= 0) | .isConnected = $isConnected | .notAfter = $notAfter' \
      <<< "$pjson" 2>/dev/null || echo "")

    if [[ -n "$updated" ]]; then
      profile_items+=("$updated")
      count=$((count + 1))
    fi
  done

  local list="[]"
  if (( ${#profile_items[@]} > 0 )); then
    list=$(printf '%s\n' "${profile_items[@]}" | jq -c -s '.')
  fi

  local out
  out=$(jq -c -n \
    --arg activeSsid "$active_ssid" \
    --argjson profiles "$list" \
    '{success: true, activeSsid: $activeSsid, profiles: $profiles}')
  safe_emit_json "$out"
}

cmd_delete() {
  local profile_id=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --id) profile_id="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  [[ -n "$profile_id" ]] || die "Profile ID required."
  profile_id=$(printf '%s' "$profile_id" | tr '[:upper:]' '[:lower:]')
  validate_profile_id "$profile_id"

  local profile_dir="$PROFILES_DIR/$profile_id"
  [[ -d "$profile_dir" && "$profile_dir" != "$PROFILES_DIR" && "$profile_dir" != "$BASE_DIR" ]] || die "Profile directory not found: $profile_id"

  local ssid="" backend="networkmanager"
  local pjson
  if pjson=$(read_safe_profile_json "$profile_dir"); then
    ssid=$(jq -r '.ssid // ""' <<< "$pjson" 2>/dev/null || echo "")
    backend=$(jq -r '.backend // "networkmanager"' <<< "$pjson" 2>/dev/null || echo "networkmanager")
  fi

  if [[ -n "$ssid" ]]; then
    if [[ "$backend" == "networkmanager" ]] && command -v nmcli >/dev/null 2>&1; then
      nmcli connection delete id "$ssid" >/dev/null 2>&1 || nmcli connection delete "$ssid" >/dev/null 2>&1 || true
    elif [[ "$backend" == "iwd" ]]; then
      local iwd_profile
      iwd_profile=$(get_iwd_profile_path "$ssid")
      if [[ -f "$iwd_profile" ]]; then
        if [[ $EUID -eq 0 ]]; then
          rm -f -- "$iwd_profile"
        elif command -v pkexec >/dev/null 2>&1; then
          pkexec rm -f -- "$iwd_profile" >/dev/null 2>&1 || true
        fi
      fi
    fi
  fi

  rm -rf "$profile_dir"
  local out
  out=$(jq -c -n --arg deleted "$profile_id" '{success: true, deleted: $deleted}')
  safe_emit_json "$out"
}

cmd_connect() {
  local ssid=""
  local profile_id_arg=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssid) ssid="$2"; shift 2 ;;
      --id)
        local query_id
        query_id=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
        if [[ "$query_id" =~ ^[a-z0-9_-]+$ && "$query_id" != "." && "$query_id" != ".." ]]; then
          local pjson
          if pjson=$(read_safe_profile_json "$PROFILES_DIR/$query_id"); then
            ssid=$(jq -r '.ssid // ""' <<< "$pjson" 2>/dev/null || echo "")
            profile_id_arg="$query_id"
          fi
        fi
        shift 2 ;;
      *) shift ;;
    esac
  done

  [[ -n "$ssid" ]] || die "SSID required to connect."

  if command -v nmcli >/dev/null 2>&1; then
    # Sanitize the existing NM connection before activating:
    # Remove any stale anonymous-identity for easyroam profiles (causes RADIUS routing failure)
    local profile_json=""
    if [[ -n "$profile_id_arg" ]]; then
      profile_json=$(read_safe_profile_json "$PROFILES_DIR/$profile_id_arg" || echo "")
    fi
    local stored_issuer=""
    local stored_crt_bytes
    if [[ -n "$profile_id_arg" && -n "$profile_json" ]] && stored_crt_bytes=$("$FD_HELPER" read "$PROFILES_DIR/$profile_id_arg/client.crt" "$MAX_CERT_CRT_SIZE" 2>/dev/null); then
      stored_issuer=$(printf '%s' "$stored_crt_bytes" | openssl x509 -noout -issuer -in /dev/stdin 2>/dev/null || echo "")
    fi
    local stored_domain=""
    if [[ -n "$profile_json" ]]; then
      stored_domain=$(printf '%s' "$profile_json" | jq -r '.domain // ""' 2>/dev/null || echo "")
    fi
    if [[ "$stored_issuer" =~ (easyroam|geteduroam|DFN-Verein) || "$stored_domain" =~ easyroam ]]; then
      nmcli connection modify id "$ssid" 802-1x.anonymous-identity "" 802-1x.system-ca-certs yes >/dev/null 2>&1 || \
        nmcli connection modify "$ssid" 802-1x.anonymous-identity "" 802-1x.system-ca-certs yes >/dev/null 2>&1 || true
    fi
    nmcli connection up id "$ssid" >/dev/null 2>&1 || nmcli connection up "$ssid" >/dev/null || die "Failed to activate $ssid via nmcli."
  elif command -v iwctl >/dev/null 2>&1; then
    local wlan_dev
    wlan_dev=$(get_wlan_iface)
    iwctl station "$wlan_dev" connect "$ssid" >/dev/null || die "Failed to connect to $ssid via iwctl."
  fi

  local out
  out=$(jq -c -n --arg connected "$ssid" '{success: true, connected: $connected}')
  safe_emit_json "$out"
}

cmd_disconnect() {
  local ssid=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssid) ssid="$2"; shift 2 ;;
      --id)
        local query_id
        query_id=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
        if [[ "$query_id" =~ ^[a-z0-9_-]+$ && "$query_id" != "." && "$query_id" != ".." ]]; then
          local pjson
          if pjson=$(read_safe_profile_json "$PROFILES_DIR/$query_id"); then
            ssid=$(jq -r '.ssid // ""' <<< "$pjson" 2>/dev/null || echo "")
          fi
        fi
        shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -n "$ssid" ]] && command -v nmcli >/dev/null 2>&1; then
    nmcli connection down id "$ssid" >/dev/null 2>&1 || nmcli connection down "$ssid" >/dev/null 2>&1 || true
  elif command -v iwctl >/dev/null 2>&1; then
    local wlan_dev
    wlan_dev=$(get_wlan_iface)
    iwctl station "$wlan_dev" disconnect >/dev/null 2>&1 || true
  fi

  local out
  out=$(jq -c -n --arg disconnected "${ssid:-all}" '{success: true, disconnected: $disconnected}')
  safe_emit_json "$out"
}

cmd_status() {
  cmd_list
}

case "${1:-}" in
  discover)   shift; cmd_discover "$@" ;;
  inspect)    shift; cmd_inspect "$@" ;;
  install)    shift; cmd_install "$@" ;;
  list)       shift; cmd_list "$@" ;;
  status)     shift; cmd_status "$@" ;;
  delete)     shift; cmd_delete "$@" ;;
  connect)    shift; cmd_connect "$@" ;;
  disconnect) shift; cmd_disconnect "$@" ;;
  *)
    echo "Usage: $0 {discover|inspect|install|list|status|delete|connect|disconnect} [args...]" >&2
    exit 1
    ;;
esac
