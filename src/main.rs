use std::{fs, io::Write};

use argh::FromArgs;
use futures::StreamExt;
use http_mitm_proxy::{hyper::header::HeaderValue, MitmProxy};
use rcgen::CertifiedKey;
use tracing_subscriber::EnvFilter;


#[derive(FromArgs)]
/// Simple MITM Proxy to modify "Range:" Headers
struct ProxyArgs {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"key.pem\".to_string()")]
    key_file: String,

    /// range header chunk
    #[argh(option, short = 'r', default = "10485760")]
    http_chunk_size: u64,
}

fn make_root_cert() -> rcgen::CertifiedKey {
    let mut param = rcgen::CertificateParams::default();

    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
    );
    param.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = param.self_signed(&key_pair).unwrap();

    rcgen::CertifiedKey { cert, key_pair }
}

fn load_root_cert(cert_path: &String, key_path: &String) -> rcgen::CertifiedKey {
    if fs::metadata(cert_path).is_err() || fs::metadata(key_path).is_err() {
        let root_cert = make_root_cert();
        if let Err(err) = write_keypair_to_pem(&root_cert, cert_path, key_path) {
            println!("Failed to write key pair: {}", err)
        }
        return root_cert;
    }
    let param = rcgen::CertificateParams::from_ca_cert_pem(&std::fs::read_to_string(cert_path).unwrap(),).unwrap();
    let key_pair = rcgen::KeyPair::from_pem(&std::fs::read_to_string(key_path).unwrap()).unwrap();
    let cert = param.self_signed(&key_pair).unwrap();
    // println!("Keypair loaded!");

    rcgen::CertifiedKey { cert, key_pair }
}

fn write_keypair_to_pem(certified_key: &CertifiedKey, cert_path: &String, key_path: &String) -> Result<(), std::io::Error> {
    let root_cert = certified_key.cert.pem();
    let private_key = certified_key.key_pair.serialize_pem();
  
    let mut root_cert_file = fs::File::create(cert_path)?;
    root_cert_file.write_all(root_cert.as_bytes())?;
  
    let mut private_key_file = fs::File::create(key_path)?;
    private_key_file.write_all(private_key.as_bytes())?;
  
    // println!("Keypair written to PEM files!");
    Ok(())
}

fn check_port(port: u16) -> bool {
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}


#[tokio::main]
async fn main() {

    let args: ProxyArgs = argh::from_env();

    if !check_port(args.port) {
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let root_cert = load_root_cert(&args.cert_file, &args.key_file);

    let proxy = MitmProxy::new(
        Some(root_cert),
        tokio_native_tls::native_tls::TlsConnector::builder()
            .request_alpns(&["h2", "http/1.1"])
            .build()
            .unwrap(),
    );

    let (mut communications, server) = proxy.bind(("127.0.0.1", args.port)).await.unwrap();

    tokio::spawn(server);

    while let Some(comm) = communications.next().await {
        let mut req = comm.request;

        if let Some(val) = req.headers().get("Range") {
            let range = val.to_str().unwrap();
            print!("Range: {}", range);
            if range.starts_with("bytes=") {
                if let Some((p1, _p2)) = range[6..].split_once('-') {
                    if let Ok(start) = p1.parse::<u64>() {
                        let newrange = format!("bytes={}-{}", start, start + args.http_chunk_size);
                        // println!("-> {}",newrange);
                        req.headers_mut().insert("Range", HeaderValue::from_str(&newrange).unwrap());
                    }
                }
            }
        }

        let _ = comm.request_back.send(req);
    }
}