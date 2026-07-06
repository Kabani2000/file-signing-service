# File Signing Service

A small service that signs an uploaded file with a **detached CAdES-BASELINE-B** signature
(CMS / PKCS#7 — RFC 5652, profiled by ETSI EN 319 122) and shows enough information to
understand and independently verify what happened.

- **Backend:** Java 25 · Spring Boot 4 · [EU DSS](https://github.com/esig/dss) 6.4 for the CAdES assembly
- **Frontend:** React 19 · Vite · TypeScript
- **Signature:** detached CAdES-BASELINE-B over the file's SHA-256 digest, ECDSA P-256
- **Verification:** any OpenSSL (`openssl cms -verify -cades`) — the signature is self-contained

---

## Run it

### Option A — Docker (one command)

```bash
docker compose up --build
```

- UI: <http://localhost:3000>
- API: <http://localhost:8080/api/sign>

### Option B — local dev

Backend (needs JDK 25):

```bash
cd backend
./mvnw spring-boot:run
```

Frontend (needs Node 20.19+ / 22.12+):

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8080
```

---

## How it works

1. The browser uploads a file to `POST /api/sign`.
2. The backend **streams** the upload through a `DigestInputStream`, computing its SHA-256
   without holding the whole file in memory.
3. EU DSS builds a **detached CAdES-BASELINE-B** signature over that digest, signed with an
   ECDSA P-256 key. The signer certificate is embedded in the signature.
4. The response is a JSON report (file digest, signer, algorithm, signing time, …) plus the
   base64-encoded `.p7s`. The UI renders the report and offers the `.p7s` for download.

The original file is never modified — the signature lives beside it as a separate `.p7s`.

## Verify a signature yourself

Save the downloaded `.p7s` next to the original file and run:

```bash
openssl cms -verify -cades -binary -inform DER \
  -in '<file>.p7s' -content '<file>' \
  -CAfile backend/src/main/resources/demo/demo-signer.pem -out /dev/null
# => CAdES Verification successful
```

Notes:
- `-binary` is required for detached binary content (no S/MIME CRLF canonicalization).
- `-CAfile demo-signer.pem` supplies the demo signer certificate as a trust anchor. It can be
  downloaded from the UI or from `GET /api/certificate` (no repo clone needed). The same
  certificate is also embedded in the `.p7s`, so the signature is self-contained:
  `openssl pkcs7 -inform DER -in <file>.p7s -print_certs` prints it.
- Tampering with the file makes verification fail (`content verify error`), as expected.
- You can also drop the `.p7s` into the [EU DSS demo validator](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo).

## Key decisions

- **Why CAdES detached?** It is one of the recognized standards named in the brief (plain CMS /
  AdES), it signs arbitrary bytes, the original file stays untouched, and it verifies with a
  single OpenSSL command — no bespoke tooling. It also sits in the eIDAS/ETSI family, so it maps
  cleanly onto a production path (see below).
- **Why sign the digest, not the file?** Signature cost is independent of file size and memory
  stays O(1) per request. Cryptographically equivalent to signing the whole file.
- **Why ECDSA P-256?** Materially faster on the signing (hot) path than RSA at comparable strength.
- **Key handling.** A self-signed EC key in a bundled PKCS#12 keystore
  (`scripts/gen-demo-keystore.sh`) — **demo material, not a secret**. The `Signer` interface is
  shaped by what a KMS/HSM or Smart-ID actually offers — sign bytes, present a certificate, never
  expose the private key — so swapping the demo `LocalKeySigner` for a production one touches
  nothing else.

## Performance & concurrency

- **Stream + digest:** uploads are hashed in bounded memory; only the 32-byte digest is signed.
- **Stateless endpoint:** scales horizontally; key material is loaded once and shared read-only.
- **Thread-safety:** the only shared state is the immutable key material inside `LocalKeySigner`.
  The genuinely stateful object — `java.security.Signature` — is created per signing call; the DSS
  service objects are cheap to construct and also created per request, which keeps every request
  free of shared mutable state.
- **Backpressure:** upload size is bounded (`spring.servlet.multipart.max-file-size`), oversized
  requests are rejected early (HTTP 413).

## Production direction (intentionally out of scope here)

- **Long-term validity:** upgrade B → B-T → B-LT → B-LTA, adding an RFC 3161 timestamp (TSA) and
  embedded revocation data. The timestamp/OCSP calls belong off the hot path (async augmentation).
- **eIDAS containers:** for QES-grade output, switch to **XAdES-in-ASiC-E** (DSS / DigiDoc4j) —
  the format the Estonian/eIDAS ecosystem uses for signed documents.
- **Identity signing:** delegate signing to the user's own key via Smart-ID / Mobile-ID (SK ID
  Solutions) so the private key never touches the backend.
- **Server-side validation endpoint** à la SiVa, producing the same report shown in the UI.

## Project layout

```
backend/    Spring Boot 4 + DSS (Java 25)
frontend/   React + Vite + TypeScript
scripts/    gen-demo-keystore.sh — regenerate the demo signing key
docker-compose.yml
```

## Tests

```bash
cd backend && ./mvnw test
```

- `SigningRoundTripTest` — signs content and verifies the produced detached CAdES signature
  against the original bytes (the same check OpenSSL performs), and proves that tampered
  content fails verification.
- `SignatureControllerTest` — the HTTP contract: report JSON for a signed upload, 400 for an
  empty or missing file part, the PEM certificate endpoint.
- `UploadLimitTest` — boots a real Tomcat to prove oversized uploads are rejected with 413
  (multipart limits are enforced by the servlet container, so MockMvc can't cover this).
