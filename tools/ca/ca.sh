#!/bin/sh
# ca.sh — Hermit Platform CA management tool
#
# Usage:
#   ca.sh init [--dir <ca-dir>]
#   ca.sh issue --name <shore-name> [--dir <ca-dir>] [--out <output-dir>]
#   ca.sh revoke --name <shore-name> [--dir <ca-dir>]
#   ca.sh list [--dir <ca-dir>]
#
# Defaults:
#   --dir  : directory of this script, i.e. tools/ca/.ca/
#   --out  : tools/ca/certs/<name>/
#
# Requirements: openssl (any version supporting rsa/x509)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_CA_DIR="${SCRIPT_DIR}/.ca"
DEFAULT_CERTS_DIR="${SCRIPT_DIR}/certs"
CA_INDEX="${DEFAULT_CA_DIR}/index.txt"
CA_REVOKED="${DEFAULT_CA_DIR}/revoked.txt"
CA_SERIAL="${DEFAULT_CA_DIR}/serial.txt"

# ── helpers ──────────────────────────────────────────────────────────────────

die() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<EOF
Hermit Platform CA Tool

USAGE:
  $(basename "$0") <command> [options]

COMMANDS:
  init                Generate a new private CA (key + self-signed cert).
                      CA cert valid for 10 years.

  issue --name <n>    Issue a client cert+key for Shore <n>.
                      CN = <n>, valid for 1 year.
                      Outputs to --out (default: certs/<n>/)

  revoke --name <n>   Add the cert serial for Shore <n> to the revocation list.

  list                Show all issued certs from the index.

OPTIONS (all commands):
  --dir  <path>       CA directory (default: .ca/)
  --out  <path>       Output directory for issued certs (issue only)
                      (default: certs/<name>/)

EXAMPLES:
  $(basename "$0") init
  $(basename "$0") issue --name shore-master
  $(basename "$0") issue --name shore-tower --out /etc/hermetic/certs/shore-tower/
  $(basename "$0") revoke --name shore-tower
  $(basename "$0") list
EOF
    exit 1
}

require_ca() {
    _ca_dir="$1"
    [ -f "${_ca_dir}/ca.key" ] || die "CA key not found at ${_ca_dir}/ca.key — run 'ca.sh init' first"
    [ -f "${_ca_dir}/ca.crt" ] || die "CA cert not found at ${_ca_dir}/ca.crt — run 'ca.sh init' first"
}

next_serial() {
    _serial_file="$1"
    if [ -f "${_serial_file}" ]; then
        _n=$(cat "${_serial_file}")
    else
        _n=1
    fi
    echo "$_n"
    echo "$((_n + 1))" > "${_serial_file}"
}

# ── commands ──────────────────────────────────────────────────────────────────

cmd_init() {
    CA_DIR="${DEFAULT_CA_DIR}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --dir) CA_DIR="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    if [ -f "${CA_DIR}/ca.key" ]; then
        echo "CA already exists at ${CA_DIR}/ca.key"
        echo "Delete it manually if you want to re-initialize."
        exit 1
    fi

    mkdir -p "${CA_DIR}"
    chmod 700 "${CA_DIR}"

    echo "Generating CA private key (4096-bit RSA)..."
    openssl genrsa -out "${CA_DIR}/ca.key" 4096
    chmod 600 "${CA_DIR}/ca.key"

    echo "Generating CA self-signed certificate (valid 10 years)..."
    openssl req -new -x509 \
        -key "${CA_DIR}/ca.key" \
        -out "${CA_DIR}/ca.crt" \
        -days 3650 \
        -subj "/CN=Hermit Platform CA/O=Hermit/OU=Infrastructure/C=US" \
        -extensions v3_ca

    # Initialize index and serial tracker
    touch "${CA_DIR}/index.txt"
    echo "1" > "${CA_DIR}/serial.txt"
    touch "${CA_DIR}/revoked.txt"

    echo ""
    echo "CA initialized:"
    echo "  Key:  ${CA_DIR}/ca.key  (KEEP SECRET — gitignored)"
    echo "  Cert: ${CA_DIR}/ca.crt  (safe to commit)"
    echo ""
    openssl x509 -in "${CA_DIR}/ca.crt" -noout -subject -issuer -dates
}

cmd_issue() {
    CA_DIR="${DEFAULT_CA_DIR}"
    SHORE_NAME=""
    OUT_DIR=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --name) SHORE_NAME="$2"; shift 2 ;;
            --dir)  CA_DIR="$2"; shift 2 ;;
            --out)  OUT_DIR="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "${SHORE_NAME}" ] || die "--name is required"
    require_ca "${CA_DIR}"

    [ -n "${OUT_DIR}" ] || OUT_DIR="${DEFAULT_CERTS_DIR}/${SHORE_NAME}"
    mkdir -p "${OUT_DIR}"

    SERIAL=$(next_serial "${CA_DIR}/serial.txt")
    KEY_FILE="${OUT_DIR}/${SHORE_NAME}.key"
    CSR_FILE="${OUT_DIR}/${SHORE_NAME}.csr"
    CRT_FILE="${OUT_DIR}/${SHORE_NAME}.crt"

    echo "Issuing cert for CN=${SHORE_NAME} (serial ${SERIAL})..."

    # Generate client key
    openssl genrsa -out "${KEY_FILE}" 2048
    chmod 600 "${KEY_FILE}"

    # Generate CSR
    openssl req -new \
        -key "${KEY_FILE}" \
        -out "${CSR_FILE}" \
        -subj "/CN=${SHORE_NAME}/O=Hermit/OU=Shore/C=US"

    # Sign with CA — produce cert valid 1 year
    openssl x509 -req \
        -in "${CSR_FILE}" \
        -CA "${CA_DIR}/ca.crt" \
        -CAkey "${CA_DIR}/ca.key" \
        -set_serial "${SERIAL}" \
        -out "${CRT_FILE}" \
        -days 365 \
        -extfile /dev/stdin <<EOF
[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

    # Clean up CSR (not needed after signing)
    rm -f "${CSR_FILE}"

    # Record in index: serial|name|cn|expiry|cert_path
    EXPIRY=$(openssl x509 -in "${CRT_FILE}" -noout -enddate | cut -d= -f2)
    echo "${SERIAL}|${SHORE_NAME}|${SHORE_NAME}|${EXPIRY}|${CRT_FILE}" >> "${CA_DIR}/index.txt"

    echo ""
    echo "Cert issued:"
    echo "  Name:   ${SHORE_NAME}"
    echo "  Serial: ${SERIAL}"
    echo "  Key:    ${KEY_FILE}"
    echo "  Cert:   ${CRT_FILE}"
    echo "  CA:     ${CA_DIR}/ca.crt"
    echo ""
    openssl x509 -in "${CRT_FILE}" -noout -subject -issuer -dates
}

cmd_revoke() {
    CA_DIR="${DEFAULT_CA_DIR}"
    SHORE_NAME=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --name) SHORE_NAME="$2"; shift 2 ;;
            --dir)  CA_DIR="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "${SHORE_NAME}" ] || die "--name is required"
    require_ca "${CA_DIR}"

    INDEX="${CA_DIR}/index.txt"
    REVOKED="${CA_DIR}/revoked.txt"

    [ -f "${INDEX}" ] || die "Index file not found: ${INDEX}"

    # Find the serial for this shore name
    SERIAL=$(grep "|${SHORE_NAME}|" "${INDEX}" | cut -d'|' -f1 | tail -1)
    [ -n "${SERIAL}" ] || die "No cert found for '${SHORE_NAME}' in index"

    # Check if already revoked
    if grep -q "^${SERIAL}$" "${REVOKED}" 2>/dev/null; then
        echo "Serial ${SERIAL} (${SHORE_NAME}) is already revoked."
        exit 0
    fi

    echo "${SERIAL}" >> "${REVOKED}"
    echo "Revoked: ${SHORE_NAME} (serial ${SERIAL})"
    echo "Updated revocation list: ${REVOKED}"
}

cmd_list() {
    CA_DIR="${DEFAULT_CA_DIR}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --dir) CA_DIR="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    INDEX="${CA_DIR}/index.txt"
    REVOKED="${CA_DIR}/revoked.txt"

    if [ ! -f "${INDEX}" ] || [ ! -s "${INDEX}" ]; then
        echo "No certs issued yet."
        exit 0
    fi

    printf "%-8s %-20s %-40s %s\n" "SERIAL" "NAME" "EXPIRES" "STATUS"
    printf "%-8s %-20s %-40s %s\n" "------" "----" "-------" "------"

    while IFS='|' read -r serial name cn expiry certpath; do
        status="valid"
        if [ -f "${REVOKED}" ] && grep -q "^${serial}$" "${REVOKED}" 2>/dev/null; then
            status="REVOKED"
        fi
        printf "%-8s %-20s %-40s %s\n" "${serial}" "${name}" "${expiry}" "${status}"
    done < "${INDEX}"
}

# ── main ─────────────────────────────────────────────────────────────────────

[ $# -gt 0 ] || usage

COMMAND="$1"
shift

case "${COMMAND}" in
    init)    cmd_init "$@" ;;
    issue)   cmd_issue "$@" ;;
    revoke)  cmd_revoke "$@" ;;
    list)    cmd_list "$@" ;;
    help|--help|-h) usage ;;
    *) die "Unknown command: ${COMMAND}. Run '$(basename "$0") help' for usage." ;;
esac
