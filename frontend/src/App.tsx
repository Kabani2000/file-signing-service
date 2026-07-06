import { useEffect, useRef, useState, type ReactNode } from "react";
import { p7sDownloadUrl, signFile, type SignatureReport } from "./api";

export function App() {
  const [report, setReport] = useState<SignatureReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function onFile(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(await signFile(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unexpected error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <header className="hero">
        <h1>File Signing Service</h1>
        <p>
          Upload a file. The backend returns a <strong>detached CAdES-BASELINE-B</strong> signature
          (RFC&nbsp;5652 / ETSI&nbsp;EN&nbsp;319&nbsp;122) you can verify with standard tools.
        </p>
      </header>

      <section
        className={`dropzone${busy ? " busy" : ""}`}
        role="button"
        tabIndex={0}
        aria-label="Upload a file to sign"
        aria-busy={busy}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          void onFile(e.dataTransfer.files[0]);
        }}
      >
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            void onFile(file);
          }}
        />
        <p className="dropzone__title">{busy ? "Signing…" : "Drop a file here or click to choose"}</p>
        <p className="dropzone__hint">The upload is only streamed to compute its SHA-256 — nothing is stored server-side.</p>
      </section>

      {error && <div className="alert">{error}</div>}

      {report && <Result report={report} />}
    </main>
  );
}

function Result({ report }: { report: SignatureReport }) {
  const [downloadUrl, setDownloadUrl] = useState<string>();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const url = p7sDownloadUrl(report);
    setDownloadUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [report]);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(timer);
  }, [copied]);

  const verifyCommand = [
    "openssl cms -verify -cades -binary -inform DER \\",
    `  -in ${shellQuote(report.signatureFileName)} -content ${shellQuote(report.fileName)} \\`,
    "  -CAfile demo-signer.pem -out /dev/null",
  ].join("\n");

  return (
    <section className="result">
      <div className="grid">
        <Card title="Signature">
          <Badge>{report.signatureFormat}</Badge>
          <Row label="Packaging" value={report.packaging} />
          <Row label="Signature algorithm" value={report.signatureAlgorithm} />
          <Row label="Digest algorithm" value={report.digestAlgorithm} />
          <Row label="Signing time" value={formatTime(report.signingTime)} />
        </Card>

        <Card title="Signed file">
          <Row label="Name" value={report.fileName} />
          <Row label="Size" value={formatBytes(report.fileSizeBytes)} />
          <Row label="SHA-256" value={report.fileSha256Hex} mono wrap />
        </Card>

        <Card title="Signer certificate">
          <Row label="Subject" value={report.signerSubjectDn} wrap />
          <Row label="Issuer" value={report.signerIssuerDn} wrap />
          <Row label="Serial" value={report.signerSerialNumber} mono />
          <Row label="Valid" value={`${formatTime(report.certificateValidFrom)} → ${formatTime(report.certificateValidUntil)}`} />
          {report.certificateSelfSigned && (
            <p className="note">Self-signed demo certificate — cryptographically valid, but not chained to a trusted CA.</p>
          )}
        </Card>
      </div>

      <div className="actions">
        <a className="btn" href={downloadUrl} download={report.signatureFileName}>
          Download {report.signatureFileName}
        </a>
        <span className="actions__hint">{formatBytes(report.signatureSizeBytes)} · detached signature</span>
      </div>

      <div className="verify">
        <h2>Verify it yourself</h2>
        <p>
          Save the signature next to the original file and run the command below
          (<code>demo-signer.pem</code> can be downloaded here — it also ships in the repo and is
          embedded in the signature itself):
        </p>
        <pre><code>{verifyCommand}</code></pre>
        <div className="actions actions--tight">
          <button
            className={`btn btn--ghost${copied ? " copied" : ""}`}
            onClick={() => {
              navigator.clipboard?.writeText(verifyCommand).then(() => setCopied(true)).catch(() => {});
            }}
          >
            {copied ? "Copied ✓" : "Copy command"}
          </button>
          <a className="btn btn--ghost" href="/api/certificate" download="demo-signer.pem">
            Download demo-signer.pem
          </a>
        </div>
      </div>
    </section>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="card">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

function Row({ label, value, mono, wrap }: { label: string; value: string; mono?: boolean; wrap?: boolean }) {
  return (
    <div className="row">
      <span className="row__label">{label}</span>
      <span className={`row__value${mono ? " mono" : ""}${wrap ? " wrap" : ""}`}>{value}</span>
    </div>
  );
}

function Badge({ children }: { children: ReactNode }) {
  return <span className="big-badge">{children}</span>;
}

function shellQuote(fileName: string): string {
  return `'${fileName.replaceAll("'", `'\\''`)}'`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}
