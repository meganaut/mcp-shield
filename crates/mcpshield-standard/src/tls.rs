use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::path::Path;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Write a private key with mode 0o600 (owner read/write only).
fn write_private_key(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
            .write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

pub struct TlsMaterial {
    pub cert_der: Vec<CertificateDer<'static>>,
    pub key_der: PrivateKeyDer<'static>,
}

pub fn load_or_generate(data_dir: &Path) -> Result<TlsMaterial> {
    let cert_path = data_dir.join("cert.pem");
    let key_path = data_dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        load_from_disk(&cert_path, &key_path)
    } else {
        generate_and_save(data_dir, &cert_path, &key_path)
    }
}

fn load_from_disk(cert_path: &Path, key_path: &Path) -> Result<TlsMaterial> {
    let cert_pem = std::fs::read(cert_path).context("read cert.pem")?;
    let key_pem = std::fs::read(key_path).context("read key.pem")?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .context("parse cert.pem")?;

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse key.pem")?
        .context("no private key in key.pem")?;

    Ok(TlsMaterial {
        cert_der: certs,
        key_der: key,
    })
}

fn generate_and_save(
    data_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<TlsMaterial> {
    std::fs::create_dir_all(data_dir).context("create data_dir")?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .context("create cert params")?;
    params.distinguished_name = DistinguishedName::new();

    let key_pair = KeyPair::generate().context("generate key pair")?;
    let cert = params.self_signed(&key_pair).context("self-sign cert")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    std::fs::write(cert_path, &cert_pem).context("write cert.pem")?;
    write_private_key(key_path, key_pem.as_bytes()).context("write key.pem")?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .context("parse generated cert")?;

    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse generated key")?
        .context("no private key generated")?;

    Ok(TlsMaterial {
        cert_der: certs,
        key_der: key,
    })
}
