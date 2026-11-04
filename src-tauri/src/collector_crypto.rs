//! 采集密钥的唯一密码学入口。保留 OAEP-SHA256 / MGF1-SHA256 和既有 label，
//! 将旧 RustCrypto RSA 私钥运算迁移至 AWS-LC；不自行实现 padding 或密钥运算。
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{
        KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
        OAEP_SHA256_MGF1SHA256,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::pki_types::{pem::PemObject, PrivateKeyDer};

pub struct PrivateKey(PrivateDecryptingKey);

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|part| std::str::from_utf8(part).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}

impl PrivateKey {
    pub fn generate() -> Result<Self, String> {
        PrivateDecryptingKey::generate(KeySize::Rsa2048)
            .map(Self)
            .map_err(|_| "采集密钥生成失败".into())
    }
    pub fn from_pem(value: &str) -> Result<Self, String> {
        let key =
            PrivateKeyDer::from_pem_slice(value.as_bytes()).map_err(|_| "本地采集私钥 PEM 无效")?;
        let PrivateKeyDer::Pkcs8(key) = key else {
            return Err("采集私钥必须为 PKCS#8".into());
        };
        PrivateDecryptingKey::from_pkcs8(key.secret_pkcs8_der())
            .map(Self)
            .map_err(|_| "本地采集私钥无效".into())
    }
    pub fn private_pem(&self) -> Result<String, String> {
        let der: Pkcs8V1Der<'_> = self.0.as_der().map_err(|_| "私钥编码失败")?;
        Ok(pem("PRIVATE KEY", der.as_ref()))
    }
    pub fn public_pem(&self) -> Result<String, String> {
        let der: PublicKeyX509Der<'_> = self.0.public_key().as_der().map_err(|_| "公钥编码失败")?;
        Ok(pem("PUBLIC KEY", der.as_ref()))
    }
    pub fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key =
            OaepPublicEncryptingKey::new(self.0.public_key()).map_err(|_| "公钥初始化失败")?;
        let mut out = vec![0; key.ciphertext_size()];
        key.encrypt(
            &OAEP_SHA256_MGF1SHA256,
            plaintext,
            &mut out,
            Some(label.as_bytes()),
        )
        .map(|data| data.to_vec())
        .map_err(|_| "密钥封装失败".into())
    }
    pub fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = OaepPrivateDecryptingKey::new(self.0.clone()).map_err(|_| "私钥初始化失败")?;
        let mut out = vec![0; key.min_output_size()];
        key.decrypt(
            &OAEP_SHA256_MGF1SHA256,
            ciphertext,
            &mut out,
            Some(label.as_bytes()),
        )
        .map(|data| data.to_vec())
        .map_err(|_| "采集密钥解封失败".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_pkcs8_identity_and_labels_stay_compatible_and_invalid_ciphertext_is_rejected() {
        let key = PrivateKey::from_pem(include_str!(
            "../../fixtures/agent-interop/test-only-private.pem"
        ))
        .unwrap();
        assert_eq!(
            key.public_pem().unwrap(),
            include_str!("../../fixtures/agent-interop/public.pem")
        );
        let ciphertext = key.encrypt("gaga-task-token/1", &[7; 32]).unwrap();
        assert_eq!(
            key.decrypt("gaga-task-token/1", &ciphertext).unwrap(),
            vec![7; 32]
        );
        assert!(key.decrypt("gaga-envelope/1", &ciphertext).is_err());
        assert!(key.decrypt("gaga-task-token/1", &[0; 256]).is_err());
        assert!(key
            .decrypt("gaga-task-token/1", &ciphertext[..200])
            .is_err());
        assert_eq!(
            PrivateKey::from_pem(&key.private_pem().unwrap())
                .unwrap()
                .public_pem()
                .unwrap(),
            key.public_pem().unwrap()
        );
    }
}
