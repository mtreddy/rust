// Post-quantum PKI CLI on ML-DSA-65 (FIPS 204).
//
//   pqc_pki keygen <name>                          -> <name>.pk, <name>.sk
//   pqc_pki issue <issuer> <subject> [--ca] [--days N]
//                                                  -> <subject>.cert, signed by <issuer>.sk
//                                                     (issuer == subject: self-signed root)
//   pqc_pki sign <name> <file>                     -> <file>.sig, signed with <name>.sk
//   pqc_pki verify <file> <sig> <root.cert> <leaf.cert> [intermediate.cert ...]
//   pqc_pki show <cert>
//   pqc_pki demo                                   run the full flow in memory

mod cert;

use cert::{Certificate, Result};
use fips204::traits::SerDes;
use std::fs;

fn read(path: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn write(path: &str, data: &[u8]) -> Result<()> {
    fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

fn load_cert(path: &str) -> Result<Certificate> {
    Certificate::from_bytes(&read(path)?)
}

fn cmd_keygen(name: &str) -> Result<()> {
    let (pk, sk) = cert::keygen()?;
    write(&format!("{name}.pk"), &pk.into_bytes())?;
    let sk_path = format!("{name}.sk");
    write(&sk_path, &sk.into_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    println!("wrote {name}.pk and {sk_path} (ML-DSA-65)");
    Ok(())
}

fn cmd_issue(issuer: &str, subject: &str, is_ca: bool, days: u64) -> Result<()> {
    let issuer_sk = cert::private_key_from_bytes(&read(&format!("{issuer}.sk"))?)?;
    let subject_pk = cert::public_key_from_bytes(&read(&format!("{subject}.pk"))?)?;
    if issuer != subject {
        // Only a CA may issue certificates.
        let issuer_cert = load_cert(&format!("{issuer}.cert"))?;
        if !issuer_cert.is_ca {
            return Err(format!("'{issuer}' is not a CA"));
        }
    }
    let c = Certificate::issue(issuer, &issuer_sk, subject, &subject_pk, is_ca, days)?;
    write(&format!("{subject}.cert"), &c.to_bytes())?;
    println!("wrote {subject}.cert\n{c}");
    Ok(())
}

fn cmd_sign(name: &str, file: &str) -> Result<()> {
    let sk = cert::private_key_from_bytes(&read(&format!("{name}.sk"))?)?;
    let sig = cert::sign_document(&sk, &read(file)?)?;
    write(&format!("{file}.sig"), &sig)?;
    println!("wrote {file}.sig ({} bytes)", sig.len());
    Ok(())
}

fn cmd_verify(file: &str, sig: &str, root: &str, leaf: &str, intermediates: &[String]) -> Result<()> {
    let intermediates = intermediates.iter().map(|p| load_cert(p)).collect::<Result<Vec<_>>>()?;
    let leaf = load_cert(leaf)?;
    cert::verify_document(&read(file)?, &read(sig)?, &leaf, &intermediates, &load_cert(root)?, cert::now())?;
    println!("OK: '{file}' signed by '{}', chain valid", leaf.subject);
    Ok(())
}

fn demo() -> Result<()> {
    let days = 365;
    println!("== keygen ==");
    let (root_pk, root_sk) = cert::keygen()?;
    let (int_pk, int_sk) = cert::keygen()?;
    let (alice_pk, alice_sk) = cert::keygen()?;
    println!("3 ML-DSA-65 key pairs: public key {} B, private key {} B",
        fips204::ml_dsa_65::PK_LEN, fips204::ml_dsa_65::SK_LEN);

    println!("\n== issue certificates ==");
    let root = Certificate::issue("Root CA", &root_sk, "Root CA", &root_pk, true, days)?;
    let int = Certificate::issue("Root CA", &root_sk, "Issuing CA", &int_pk, true, days)?;
    let alice = Certificate::issue("Issuing CA", &int_sk, "alice", &alice_pk, false, days)?;
    println!("root:\n{root}\nintermediate:\n{int}\nleaf:\n{alice}");

    // Round-trip through bytes like a real file / network transfer.
    let alice = Certificate::from_bytes(&alice.to_bytes())?;
    let chain = [int.clone()];

    println!("\n== sign / verify document ==");
    let doc = b"transfer 10 ETH to bob";
    let sig = cert::sign_document(&alice_sk, doc)?;
    println!("signature: {} bytes", sig.len());
    let at = cert::now();
    let check = |label: &str, r: Result<()>| match r {
        Ok(()) => println!("{label:<34} OK"),
        Err(e) => println!("{label:<34} REJECTED: {e}"),
    };
    check("valid document + chain", cert::verify_document(doc, &sig, &alice, &chain, &root, at));
    check("tampered document", cert::verify_document(b"transfer 99 ETH to eve", &sig, &alice, &chain, &root, at));
    check("missing intermediate", cert::verify_document(doc, &sig, &alice, &[], &root, at));
    let (evil_pk, evil_sk) = cert::keygen()?;
    let evil_root = Certificate::issue("Root CA", &evil_sk, "Root CA", &evil_pk, true, days)?;
    check("untrusted root with same name", cert::verify_document(doc, &sig, &alice, &chain, &evil_root, at));
    check("after expiry", cert::verify_document(doc, &sig, &alice, &chain, &root, at + 400 * 86_400));
    let mut forged = alice.clone();
    forged.subject = "mallory".into();
    check("edited certificate subject", cert::verify_document(doc, &sig, &forged, &chain, &root, at));
    // A leaf (non-CA) trying to act as an issuer.
    let (bob_pk, _) = cert::keygen()?;
    let bob = Certificate::issue("alice", &alice_sk, "bob", &bob_pk, false, days)?;
    check("cert issued by non-CA leaf", cert::verify_chain(&bob, &[alice.clone(), int.clone()], &root, at));
    // Document signature replayed as a certificate signature: rejected by context separation.
    check("doc sig reused across contexts", {
        let mut c = alice.clone();
        c.signature = sig;
        cert::verify_chain(&c, &chain, &root, at)
    });
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["keygen", name] => cmd_keygen(name),
        ["issue", issuer, subject, rest @ ..] => {
            let is_ca = rest.contains(&"--ca");
            let days = match rest.iter().position(|&x| x == "--days") {
                Some(i) => rest.get(i + 1).ok_or("--days needs a value")?.parse().map_err(|_| "bad --days")?,
                None => 365,
            };
            cmd_issue(issuer, subject, is_ca, days)
        }
        ["sign", name, file] => cmd_sign(name, file),
        ["verify", file, sig, root, leaf, ..] => cmd_verify(file, sig, root, leaf, &args[5..]),
        ["show", path] => load_cert(path).map(|c| println!("{c}")),
        ["demo"] => demo(),
        _ => Err("usage: see the header comment in src/main.rs\n  keygen | issue | sign | verify | show | demo".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pki() -> (Certificate, Certificate, Certificate, fips204::ml_dsa_65::PrivateKey) {
        let (rpk, rsk) = cert::keygen().unwrap();
        let (ipk, isk) = cert::keygen().unwrap();
        let (lpk, lsk) = cert::keygen().unwrap();
        let root = Certificate::issue("root", &rsk, "root", &rpk, true, 1).unwrap();
        let int = Certificate::issue("root", &rsk, "int", &ipk, true, 1).unwrap();
        let leaf = Certificate::issue("int", &isk, "leaf", &lpk, false, 1).unwrap();
        (root, int, leaf, lsk)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (root, int, leaf, sk) = pki();
        let sig = cert::sign_document(&sk, b"doc").unwrap();
        let leaf = Certificate::from_bytes(&leaf.to_bytes()).unwrap();
        assert!(cert::verify_document(b"doc", &sig, &leaf, &[int.clone()], &root, cert::now()).is_ok());
        assert!(cert::verify_document(b"dox", &sig, &leaf, &[int], &root, cert::now()).is_err());
    }

    #[test]
    fn chain_failures() {
        let (root, int, leaf, _) = pki();
        let now = cert::now();
        assert!(cert::verify_chain(&leaf, &[], &root, now).is_err()); // missing intermediate
        assert!(cert::verify_chain(&leaf, &[int.clone()], &root, now + 2 * 86_400).is_err()); // expired
        let mut bad = leaf.clone();
        bad.is_ca = true; // privilege escalation by editing the cert
        assert!(cert::verify_chain(&bad, &[int], &root, now).is_err());
    }

    #[test]
    fn parse_rejects_garbage() {
        let (root, ..) = pki();
        let mut b = root.to_bytes();
        assert!(Certificate::from_bytes(&b[..100]).is_err());
        b.push(0);
        assert!(Certificate::from_bytes(&b).is_err());
    }
}
