#!/usr/bin/env bash
#
# Generates the self-signed EC P-256 demo signing key used by the service.
#
# This is DEMO key material — the password is intentionally public and the certificate
# is self-signed. In production the private key would live in a KMS/HSM and never be
# exported. Re-run this script to rotate the demo key.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../backend/src/main/resources/demo"
KEYSTORE="${OUT_DIR}/demo-keystore.p12"
CERT_PEM="${OUT_DIR}/demo-signer.pem"

ALIAS="demo-signer"
STOREPASS="demo-password"
DNAME="CN=File Signing Demo, OU=Engineering, O=File Signing Service, C=EE"

mkdir -p "${OUT_DIR}"
rm -f "${KEYSTORE}" "${CERT_PEM}"

keytool -genkeypair \
  -alias "${ALIAS}" \
  -keyalg EC -groupname secp256r1 \
  -sigalg SHA256withECDSA \
  -validity 825 \
  -dname "${DNAME}" \
  -keystore "${KEYSTORE}" -storetype PKCS12 \
  -storepass "${STOREPASS}" -keypass "${STOREPASS}"

keytool -exportcert -rfc \
  -alias "${ALIAS}" \
  -keystore "${KEYSTORE}" -storepass "${STOREPASS}" \
  -file "${CERT_PEM}"

echo "Generated:"
echo "  ${KEYSTORE}"
echo "  ${CERT_PEM}"
