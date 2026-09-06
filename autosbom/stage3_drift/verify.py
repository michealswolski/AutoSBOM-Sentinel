"""Baseline signature verification (cosign wrapper).

The drift daemon's trust anchor is its baseline inventory. An unsigned (or
unverifiable) baseline could itself be tampered with — the exact loop the
signing addition closes (docs/01_ARCHITECTURE.md, Priority Addition A).

Policy:
  - require_signature=True (default): a baseline whose cosign verification
    fails or cannot be performed is REJECTED and the daemon refuses to run.
  - require_signature=False: verification is skipped with a loud note; meant
    only for development on machines without cosign — the daemon records in
    every event log that it is running with an UNVERIFIED baseline.

Verification uses `cosign verify-blob` with a keyless certificate identity
(GitHub OIDC) or a fixed public key, matching signing/sign_baseline.sh.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class BaselineVerificationError(RuntimeError):
    pass


@dataclass
class VerificationPolicy:
    require_signature: bool = True
    # Keyless verification (preferred): expected cert identity + OIDC issuer.
    certificate_identity: str = ""
    certificate_oidc_issuer: str = "https://token.actions.githubusercontent.com"
    # Or key-based verification:
    public_key_path: str = ""


def verify_baseline(
    baseline_path: str | Path,
    signature_path: str | Path,
    policy: VerificationPolicy,
    certificate_path: str | Path | None = None,
) -> bool:
    """Verify the baseline file's cosign signature.

    Returns True on verified. Raises BaselineVerificationError when the
    policy requires a signature and verification fails or can't run.
    Returns False (with no exception) only when the policy explicitly does
    not require signatures.
    """
    baseline_path = Path(baseline_path)
    signature_path = Path(signature_path)

    if not policy.require_signature:
        return False  # explicitly unverified — caller must record this loudly

    if shutil.which("cosign") is None:
        raise BaselineVerificationError(
            "cosign is not installed but the verification policy requires a "
            "signed baseline. Install cosign, or (development only) run with "
            "--allow-unverified-baseline."
        )
    if not signature_path.exists():
        raise BaselineVerificationError(
            f"baseline signature not found: {signature_path}"
        )

    cmd = ["cosign", "verify-blob", "--signature", str(signature_path)]
    if policy.public_key_path:
        cmd += ["--key", policy.public_key_path]
    else:
        if not policy.certificate_identity:
            raise BaselineVerificationError(
                "verification policy has neither a public key nor a "
                "certificate identity configured"
            )
        cmd += [
            "--certificate-identity", policy.certificate_identity,
            "--certificate-oidc-issuer", policy.certificate_oidc_issuer,
        ]
        if certificate_path:
            cmd += ["--certificate", str(certificate_path)]
    cmd.append(str(baseline_path))

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise BaselineVerificationError(
            f"cosign verification FAILED for {baseline_path}: "
            f"{result.stderr.strip()[:500]}"
        )
    return True
