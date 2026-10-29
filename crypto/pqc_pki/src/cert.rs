// Minimal post-quantum PKI on ML-DSA-65 (FIPS 204, "Dilithium").
//
// Certificate = to-be-signed (TBS) fields + issuer's ML-DSA signature over them:
//   magic | alg | serial | issuer | subject | not_before | not_after | is_ca | public key
//
// This is a simple custom binary format, not X.509/DER. Real PQC certificates use
// X.509 with the ML-DSA OIDs (RFC 9881), but the trust logic is the same:
// each certificate is signed by its parent, up to a trusted self-signed root.
//
// FIPS 204 signatures take a "context" string. Certificates and documents are
// signed under different contexts, so a document signature can never be replayed
// as a certificate signature (or vice versa).

use fips204::ml_dsa_65::{self, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, String>;

const MAGIC: &[u8; 8] = b"PQCCERT1";
const ALG: &str = "ML-DSA-65";
pub const CTX_CERT: &[u8] = b"pqc-pki/cert/v1";
pub const CTX_DOC: &[u8] = b"pqc-pki/doc/v1";

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ---------- keys ----------

pub fn keygen() -> Result<(PublicKey, PrivateKey)> {
    ml_dsa_65::try_keygen().map_err(String::from)
}

pub fn public_key_from_bytes(b: &[u8]) -> Result<PublicKey> {
    let arr: [u8; PK_LEN] = b.try_into().map_err(|_| format!("public key must be {PK_LEN} bytes"))?;
    PublicKey::try_from_bytes(arr).map_err(String::from)
}

pub fn private_key_from_bytes(b: &[u8]) -> Result<PrivateKey> {
    let arr: [u8; SK_LEN] = b.try_into().map_err(|_| format!("private key must be {SK_LEN} bytes"))?;
    PrivateKey::try_from_bytes(arr).map_err(String::from)
}

// ---------- documents ----------

pub fn sign_document(sk: &PrivateKey, data: &[u8]) -> Result<[u8; SIG_LEN]> {
    sk.try_sign(data, CTX_DOC).map_err(String::from)
}

/// Verify a document signature AND that the signer's certificate chains to `root`.
pub fn verify_document(
    data: &[u8],
    sig: &[u8],
    leaf: &Certificate,
    intermediates: &[Certificate],
    root: &Certificate,
    at: u64,
) -> Result<()> {
    verify_chain(leaf, intermediates, root, at)?;
    let sig: [u8; SIG_LEN] = sig.try_into().map_err(|_| format!("signature must be {SIG_LEN} bytes"))?;
    if !leaf.public_key()?.verify(data, &sig, CTX_DOC) {
        return Err("document signature invalid".into());
    }
    Ok(())
}

// ---------- certificates ----------

#[derive(Clone)]
pub struct Certificate {
    pub serial: [u8; 16],
    pub issuer: String,
    pub subject: String,
    pub not_before: u64,
    pub not_after: u64,
    pub is_ca: bool,
    pub public_key: [u8; PK_LEN],
    pub signature: [u8; SIG_LEN],
}

impl Certificate {
    /// Issue a certificate for `subject_pk`, signed by `issuer_sk`.
    /// For a self-signed root, pass the root's own name and key.
    pub fn issue(
        issuer: &str,
        issuer_sk: &PrivateKey,
        subject: &str,
        subject_pk: &PublicKey,
        is_ca: bool,
        days: u64,
    ) -> Result<Self> {
        let mut serial = [0u8; 16];
        OsRng.fill_bytes(&mut serial);
        let start = now();
        let mut cert = Certificate {
            serial,
            issuer: issuer.into(),
            subject: subject.into(),
            not_before: start,
            not_after: start + days * 86_400,
            is_ca,
            public_key: subject_pk.clone().into_bytes(),
            signature: [0u8; SIG_LEN],
        };
        cert.signature = issuer_sk.try_sign(&cert.tbs_bytes(), CTX_CERT)?;
        Ok(cert)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::try_from_bytes(self.public_key).map_err(String::from)
    }

    pub fn is_self_signed(&self) -> bool {
        self.issuer == self.subject
    }

    /// Check this certificate's signature with the issuer's public key.
    pub fn verify_signature(&self, issuer_pk: &PublicKey) -> bool {
        issuer_pk.verify(&self.tbs_bytes(), &self.signature, CTX_CERT)
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.to_bytes()))
    }

    fn tbs_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(MAGIC);
        put_bytes(&mut w, ALG.as_bytes());
        w.extend_from_slice(&self.serial);
        put_bytes(&mut w, self.issuer.as_bytes());
        put_bytes(&mut w, self.subject.as_bytes());
        w.extend_from_slice(&self.not_before.to_be_bytes());
        w.extend_from_slice(&self.not_after.to_be_bytes());
        w.push(self.is_ca as u8);
        w.extend_from_slice(&self.public_key);
        w
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = self.tbs_bytes();
        w.extend_from_slice(&self.signature);
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader { b, pos: 0 };
        if r.take(8)? != MAGIC {
            return Err("not a PQC certificate".into());
        }
        if r.bytes()? != ALG.as_bytes() {
            return Err(format!("unsupported algorithm, expected {ALG}"));
        }
        let cert = Certificate {
            serial: r.array()?,
            issuer: r.string()?,
            subject: r.string()?,
            not_before: u64::from_be_bytes(r.array()?),
            not_after: u64::from_be_bytes(r.array()?),
            is_ca: match r.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err("bad is_ca flag".into()),
            },
            public_key: r.array()?,
            signature: r.array()?,
        };
        if r.pos != b.len() {
            return Err("trailing bytes after certificate".into());
        }
        Ok(cert)
    }
}

impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "  subject:     {}", self.subject)?;
        writeln!(f, "  issuer:      {}", self.issuer)?;
        writeln!(f, "  serial:      {}", hex::encode(self.serial))?;
        writeln!(f, "  algorithm:   {ALG}")?;
        writeln!(f, "  validity:    {} .. {} (unix secs)", self.not_before, self.not_after)?;
        writeln!(f, "  is CA:       {}", self.is_ca)?;
        writeln!(f, "  key / sig:   {PK_LEN} / {SIG_LEN} bytes")?;
        write!(f, "  fingerprint: {}", self.fingerprint())
    }
}

/// Validate leaf -> intermediates... -> root. `root` is the verifier's trust anchor.
pub fn verify_chain(leaf: &Certificate, intermediates: &[Certificate], root: &Certificate, at: u64) -> Result<()> {
    if !root.is_self_signed() || !root.is_ca || !root.verify_signature(&root.public_key()?) {
        return Err(format!("root '{}' is not a valid self-signed CA", root.subject));
    }

    let path: Vec<&Certificate> = std::iter::once(leaf).chain(intermediates).chain(std::iter::once(root)).collect();
    for cert in &path {
        if at < cert.not_before || at > cert.not_after {
            return Err(format!("certificate '{}' is expired or not yet valid", cert.subject));
        }
    }
    for pair in path.windows(2) {
        let (child, parent) = (pair[0], pair[1]);
        if child.issuer != parent.subject {
            return Err(format!("'{}' was issued by '{}', not '{}'", child.subject, child.issuer, parent.subject));
        }
        if !parent.is_ca {
            return Err(format!("'{}' is not a CA and cannot issue certificates", parent.subject));
        }
        if !child.verify_signature(&parent.public_key()?) {
            return Err(format!("signature on '{}' is invalid", child.subject));
        }
    }
    Ok(())
}

// ---------- encoding helpers ----------

fn put_bytes(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_be_bytes());
    w.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("truncated certificate")?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const L: usize>(&mut self) -> Result<[u8; L]> {
        Ok(self.take(L)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| "invalid utf-8 name".into())
    }
}
