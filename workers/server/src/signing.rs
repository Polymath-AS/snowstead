//! Nix narinfo rendering and per-cache signing. Keys are selected from a fresh
//! cache row for each render; failed unsealing never falls back to a shared key.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::http::StatusCode;
use base64::{
    Engine,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::{config::Config, error::ApiError};

const NIX32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub struct Narinfo {
    pub store_path: String,
    pub store_path_hash: String,
    pub nar_hash: String,
    pub nar_size: i64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub system: Option<String>,
    pub signatures: Vec<String>,
    pub file_hash: String,
    pub file_size: i64,
    pub compression: String,
}

/// Nix base32, not RFC 4648: high groups first, from little-endian bytes.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub(crate) fn nix32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    for n in (0..(bytes.len() * 8).div_ceil(5)).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;
        let digit = (bytes[i] as u16 >> shift)
            | ((bytes.get(i + 1).copied().unwrap_or(0) as u16) << (8 - shift));
        out.push(NIX32[(digit & 31) as usize] as char);
    }
    out
}

/// SHA256 SRI, lowercase hex, or canonical Nix base32, as cache-domain accepts.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub(crate) fn parse_nar_hash(raw: &str) -> Option<[u8; 32]> {
    if let Some(sri) = raw.strip_prefix("sha256-") {
        if sri.len() != 44
            || !sri.ends_with('=')
            || !sri.as_bytes()[..43]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"+/".contains(c))
        {
            return None;
        }
        // WebCrypto's atob also accepts nonzero unused trailing bits.
        return GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        )
        .decode(sri)
        .ok()?
        .try_into()
        .ok();
    }
    let hash = raw.strip_prefix("sha256:")?;
    if hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return hex::decode(hash).ok()?.try_into().ok();
    }
    if hash.len() != 52 {
        return None;
    }
    let mut out = [0u8; 32];
    for (n, c) in hash.bytes().rev().enumerate() {
        let digit = NIX32.iter().position(|&b| b == c)? as u8;
        if n == 51 && digit > 1 {
            return None;
        }
        let i = n * 5 / 8;
        let shift = n * 5 % 8;
        out[i] |= digit << shift;
        if shift != 0 && i + 1 < out.len() {
            out[i + 1] |= digit >> (8 - shift);
        }
    }
    Some(out)
}

fn signing_error() -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Cannot sign narinfo")
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._/+-".contains(&c))
}

// atob-compatible decoding for persisted keys: optional padding and whitespace.
fn decode_key(text: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let compact = Zeroizing::new(
        text.bytes()
            .filter(|c| !b" \t\n\r\x0c".contains(c))
            .collect::<Vec<_>>(),
    );
    GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(&*compact)
    .map(Zeroizing::new)
    .map_err(|_| signing_error())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
fn import_key(bytes: &[u8]) -> Result<SigningKey, ApiError> {
    if bytes.len() != 32 && bytes.len() != 64 {
        return Err(signing_error());
    }
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).map_err(|_| signing_error())?);
    let key = SigningKey::from_bytes(&seed);
    if bytes.len() == 64 && key.verifying_key().as_bytes() != &bytes[32..] {
        return Err(signing_error());
    }
    Ok(key)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
fn unseal(
    config: &Config,
    cache_id: i32,
    name: &str,
    public: &str,
    sealed: &str,
) -> Result<SigningKey, ApiError> {
    if !valid_name(name) {
        return Err(signing_error());
    }
    let parts: Vec<_> = sealed.split(':').collect();
    let (material, aad) = match parts.as_slice() {
        ["v1", material] => (*material, format!("cache:{cache_id}").into_bytes()),
        ["v2", id, material] if !id.is_empty() => (
            *material,
            serde_json::to_vec(&("v2", cache_id, id, name, public)).map_err(|_| signing_error())?,
        ),
        _ => return Err(signing_error()),
    };
    let master = decode_key(&config.signing_master_key)?;
    if master.len() != 32 {
        return Err(signing_error());
    }
    let cipher = Aes256Gcm::new_from_slice(&master).map_err(|_| signing_error())?;
    let ciphertext = decode_key(material)?;
    // 12-byte IV + 64-byte Nix secret + 16-byte authentication tag.
    if ciphertext.len() != 92 {
        return Err(signing_error());
    }
    let nonce = Nonce::try_from(&ciphertext[..12]).map_err(|_| signing_error())?;
    let secret = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext[12..],
                    aad: &aad,
                },
            )
            .map_err(|_| signing_error())?,
    );
    let key = import_key(&secret)?;
    if public != format!("{name}:{}", STANDARD.encode(key.verifying_key().as_bytes())) {
        return Err(signing_error());
    }
    Ok(key)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub(crate) fn select_key(
    config: &Config,
    cache_id: i32,
    name: Option<&str>,
    public: Option<&str>,
    sealed: Option<&str>,
) -> Result<Option<(String, SigningKey)>, ApiError> {
    // Any populated column means per-cache signing; incomplete rows fail closed.
    if name.is_some() || public.is_some() || sealed.is_some() {
        let (name, public, sealed) = (
            name.ok_or_else(signing_error)?,
            public.ok_or_else(signing_error)?,
            sealed.ok_or_else(signing_error)?,
        );
        return Ok(Some((
            name.to_owned(),
            unseal(config, cache_id, name, public, sealed)?,
        )));
    }
    if config.require_cache_signing_keys {
        return Err(signing_error());
    }
    if config.signing_private_key.is_empty() {
        return Ok(None);
    }
    if !valid_name(&config.signing_key_name) {
        return Err(signing_error());
    }
    let secret = decode_key(&config.signing_private_key)?;
    Ok(Some((
        config.signing_key_name.clone(),
        import_key(&secret)?,
    )))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn render<'a>(
    connection: impl sqlx::Executor<'a, Database = sqlx::Postgres>,
    config: &Config,
    cache_id: i32,
    cache_path: &str,
    is_private: bool,
    nar: &Narinfo,
) -> Result<String, ApiError> {
    struct SigningKeys {
        signing_key_name: Option<String>,
        signing_public_key: Option<String>,
        signing_key_sealed: Option<String>,
    }
    let keys = sqlx::query_as!(
        SigningKeys,
        r#"
        SELECT
            signing_key_name,
            signing_public_key,
            signing_key_sealed
        FROM caches
        WHERE id = $1
        "#,
        cache_id,
    )
    .fetch_optional(connection)
    .await?
    .ok_or_else(signing_error)?;
    let key = select_key(
        config,
        cache_id,
        keys.signing_key_name.as_deref(),
        keys.signing_public_key.as_deref(),
        keys.signing_key_sealed.as_deref(),
    )?;
    render_with_key(
        cache_path,
        is_private,
        nar,
        key.as_ref().map(|(name, key)| (name.as_str(), key)),
    )
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub(crate) fn render_with_key(
    cache_path: &str,
    is_private: bool,
    nar: &Narinfo,
    key: Option<(&str, &SigningKey)>,
) -> Result<String, ApiError> {
    let digest = parse_nar_hash(&nar.nar_hash).ok_or_else(signing_error)?;
    let hash = format!("sha256:{}", nix32(&digest));
    let prefix = if is_private {
        String::new()
    } else {
        "../".repeat(cache_path.split('/').count())
    };
    let mut lines = vec![
        format!("StorePath: {}", nar.store_path),
        format!("URL: {prefix}nar/{}/{}.nar", nar.file_hash, nar.compression),
        format!("Compression: {}", nar.compression),
        format!("FileHash: sha256:{}", nar.file_hash),
        format!("FileSize: {}", nar.file_size),
        format!("NarHash: {hash}"),
        format!("NarSize: {}", nar.nar_size),
    ];
    if !nar.references.is_empty() {
        lines.push(format!("References: {}", nar.references.join(" ")));
    }
    if let Some(deriver) = nar.deriver.as_deref().filter(|s| !s.is_empty()) {
        let deriver = deriver.strip_prefix("/nix/store/").unwrap_or(deriver);
        lines.push(format!("Deriver: {deriver}"));
    }
    if let Some(system) = nar.system.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("System: {system}"));
    }
    lines.extend(nar.signatures.iter().map(|sig| format!("Sig: {sig}")));
    if let Some((name, key)) = key {
        let refs = nar
            .references
            .iter()
            .map(|r| format!("/nix/store/{r}"))
            .collect::<Vec<_>>()
            .join(",");
        let fingerprint = format!("1;{};{hash};{};{refs}", nar.store_path, nar.nar_size);
        lines.push(format!(
            "Sig: {name}:{}",
            STANDARD.encode(key.sign(fingerprint.as_bytes()).to_bytes())
        ));
    }
    Ok(lines.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signature;

    // Independently generated with Node WebCrypto, not this implementation:
    // seed = 0..31, master = 255..224, IV = 0..11 (v1), 12..23 (v2).
    // AES-GCM encrypts seed || raw public key, with tagLength=128 and AAD
    // TextEncoder("cache:7") or JSON.stringify(["v2", 7, id, name, public]).
    const MASTER: &str = "//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=";
    const SECRET: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8DoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuA==";
    const PUBLIC: &str = "fixture-7:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
    const V1: &str = "v1:AAECAwQFBgcICQoL15P7C+CuGBOYkfUIZ/FpsPy08Gnn4TVOFBgDWqGGlnWl39X2SQWas46wkv0A7rKoZxW2P436mJurLbWFiDmFpm7lx0toK97AInKhswaL+HU=";
    const V2: &str = "v2:019a3b4c-5678-7000-8000-000000000007:DA0ODxAREhMUFRYXJhawBYFJ7CEgX1UFMVM4mhW8bsOfJk5TVI46s/BSbyHCivqipo7Iv5cX0JoKHeVmhpbZ6myOVJjmgA2IDUgP9Vgr3Sv345GAjTzwzgUgkcI=";
    const HASH: &str = "sha256:02crsn39w9wxan1z3dz9g1zb76l09jb462qzb3q8r8zic4p2k6rg";
    const SRI: &str = "sha256-L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=";
    const HEX: &str = "sha256:2f9b292e61f1a38cf0581f0b43964c809ab37e78e9b7f183559d279e86d59909";
    const FINGERPRINT: &str = "1;/nix/store/00000000000000000000000000000000-example;sha256:02crsn39w9wxan1z3dz9g1zb76l09jb462qzb3q8r8zic4p2k6rg;123456;/nix/store/11111111111111111111111111111111-z,/nix/store/00000000000000000000000000000000-a";
    const SIGNATURE: &str =
        "apZqoQNBhNJtUROvUikXIstBhv7HXo/4i4G/pJ8QMiSrk1ee3E0jF5cAV27y6NFdpVw5Z2x2iK5Cz5aI3yknBQ==";

    fn config() -> Config {
        Config {
            signing_master_key: MASTER.into(),
            signing_key_name: "shared".into(),
            ..Config::default()
        }
    }

    fn nar() -> Narinfo {
        Narinfo {
            store_path: "/nix/store/00000000000000000000000000000000-example".into(),
            store_path_hash: "00000000000000000000000000000000".into(),
            nar_hash: SRI.into(),
            nar_size: 123456,
            // Preserve reference order, even when it isn't sorted.
            references: vec![
                "11111111111111111111111111111111-z".into(),
                "00000000000000000000000000000000-a".into(),
            ],
            deriver: Some("00000000000000000000000000000000-example.drv".into()),
            system: Some("x86_64-linux".into()),
            signatures: vec!["upstream:kept".into()],
            file_hash: "a".repeat(64),
            file_size: 98765,
            compression: "zstd".into(),
        }
    }

    #[test]
    fn canonical_hash_forms_and_invalid_inputs() {
        let digest = parse_nar_hash(HEX).unwrap();
        for input in [SRI, HEX, HASH] {
            assert_eq!(parse_nar_hash(input), Some(digest));
            assert_eq!(format!("sha256:{}", nix32(&digest)), HASH);
        }
        for bad in [
            "".into(),
            "0".repeat(52),
            format!("sha256:{}", "0".repeat(51)),
            format!("sha256:{}", "0".repeat(53)),
            format!("sha256:{}", "z".repeat(52)),
            format!("sha256:{}e", "0".repeat(51)),
            HEX.to_uppercase(),
            SRI.trim_end_matches('=').into(),
            SRI.replace('=', "!"),
            format!("sha256-{}", "é".repeat(22)),
            format!("md5:{}", "0".repeat(52)),
        ] {
            assert_eq!(parse_nar_hash(&bad), None, "{bad}");
        }
        // cache-domain's SRI decoder, like atob, ignores unused trailing bits.
        assert_eq!(parse_nar_hash(&SRI.replace("Qk=", "Ql=")), Some(digest));
    }

    #[test]
    fn nix32_bit_order_and_boundaries() {
        assert_eq!(nix32(&[]), "");
        assert_eq!(nix32(&[255]), "7z");
        assert_eq!(nix32(&[255; 32]), format!("1{}", "z".repeat(51)));
        for bit in 0..256 {
            let mut bytes = [0u8; 32];
            bytes[bit / 8] = 1 << (bit % 8);
            assert_eq!(
                parse_nar_hash(&format!("sha256:{}", nix32(&bytes))),
                Some(bytes)
            );
        }
    }

    #[test]
    fn webcrypto_v1_and_v2_unseal_and_sign() {
        for sealed in [V1, V2] {
            let key = unseal(&config(), 7, "fixture-7", PUBLIC, sealed).unwrap();
            let signature = key.sign(FINGERPRINT.as_bytes());
            assert_eq!(STANDARD.encode(signature.to_bytes()), SIGNATURE);
            key.verifying_key()
                .verify_strict(FINGERPRINT.as_bytes(), &signature)
                .unwrap();
            assert!(
                key.verifying_key()
                    .verify_strict(b"changed fingerprint", &signature)
                    .is_err()
            );
        }
    }

    #[test]
    fn webcrypto_seals_reject_tampering_and_cross_cache_replay() {
        for sealed in [V1, V2] {
            assert!(unseal(&config(), 8, "fixture-7", PUBLIC, sealed).is_err());
            for offset in [0, 12, 75, 91] {
                // IV, ciphertext, and tag
                let (prefix, material) = sealed.rsplit_once(':').unwrap();
                let mut bytes = STANDARD.decode(material).unwrap();
                bytes[offset] ^= 1;
                let tampered = format!("{prefix}:{}", STANDARD.encode(bytes));
                assert!(unseal(&config(), 7, "fixture-7", PUBLIC, &tampered).is_err());
            }
            let mut wrong_master = config();
            wrong_master.signing_master_key = STANDARD.encode([0; 32]);
            assert!(unseal(&wrong_master, 7, "fixture-7", PUBLIC, sealed).is_err());
            assert!(unseal(&Config::default(), 7, "fixture-7", PUBLIC, sealed).is_err());
        }
        let renamed_public = PUBLIC.replace("fixture-7", "renamed");
        assert!(unseal(&config(), 7, "renamed", &renamed_public, V2).is_err());
        assert!(
            unseal(
                &config(),
                7,
                "fixture-7",
                &PUBLIC.replace("A6EH", "B6EH"),
                V2
            )
            .is_err()
        );
        assert!(
            unseal(
                &config(),
                7,
                "fixture-7",
                PUBLIC,
                &V2.replace("019a3b4c", "019a3b4d")
            )
            .is_err()
        );
        // v1 authenticated only the cache ID, but the advertised public key
        // must still match the decrypted secret and its name.
        assert!(
            unseal(
                &config(),
                7,
                "fixture-7",
                &PUBLIC.replace("A6EH", "B6EH"),
                V1
            )
            .is_err()
        );
        for bad in [
            "",
            "v1:",
            "v1:AA==",
            "v3:abc",
            "v2::abc",
            "v2:id:abc",
            "v1:abc:extra",
        ] {
            assert!(unseal(&config(), 7, "fixture-7", PUBLIC, bad).is_err());
        }
    }

    #[test]
    fn required_keys_and_partial_rows_never_fall_back() {
        let mut cfg = config();
        cfg.signing_private_key = SECRET.into();
        assert!(select_key(&cfg, 7, None, None, None).unwrap().is_some());
        for mask in 1..8 {
            let name = (mask & 1 != 0).then_some("fixture-7");
            let public = (mask & 2 != 0).then_some(PUBLIC);
            let sealed = (mask & 4 != 0).then_some("corrupt");
            assert!(select_key(&cfg, 7, name, public, sealed).is_err());
        }
        assert!(select_key(&cfg, 7, Some(""), Some(""), Some("")).is_err());
        cfg.require_cache_signing_keys = true;
        assert!(select_key(&cfg, 7, None, None, None).is_err());
        cfg.require_cache_signing_keys = false;
        cfg.signing_private_key.clear();
        assert!(select_key(&cfg, 7, None, None, None).unwrap().is_none());
    }

    #[test]
    fn malformed_secret_material_is_rejected() {
        for len in [0, 1, 31, 33, 63, 65] {
            assert!(import_key(&vec![0; len]).is_err());
        }
        let mut secret = STANDARD.decode(SECRET).unwrap();
        assert_eq!(
            import_key(&secret[..32]).unwrap().verifying_key(),
            import_key(&secret).unwrap().verifying_key()
        );
        secret[63] ^= 1;
        assert!(import_key(&secret).is_err());
        for name in ["", "-bad", "bad:key", "bad\nname"] {
            assert!(!valid_name(name));
        }
        assert!(!valid_name(&"a".repeat(201)));
        assert!(valid_name("valid._/+-1"));
        assert!(decode_key("!!!!").is_err());
        assert_eq!(&*decode_key(" YQ \n").unwrap(), b"a");
    }

    #[test]
    fn rendering_matches_webcrypto_signature_and_preserves_fields() {
        let key = unseal(&config(), 7, "fixture-7", PUBLIC, V2).unwrap();
        let body = render_with_key("org/cache", false, &nar(), Some(("fixture-7", &key))).unwrap();
        let expected = format!(
            "StorePath: /nix/store/00000000000000000000000000000000-example\nURL: ../../nar/{}/zstd.nar\nCompression: zstd\nFileHash: sha256:{}\nFileSize: 98765\nNarHash: {HASH}\nNarSize: 123456\nReferences: 11111111111111111111111111111111-z 00000000000000000000000000000000-a\nDeriver: 00000000000000000000000000000000-example.drv\nSystem: x86_64-linux\nSig: upstream:kept\nSig: fixture-7:{SIGNATURE}\n",
            "a".repeat(64),
            "a".repeat(64)
        );
        assert_eq!(body, expected);
        let sig = Signature::from_slice(&STANDARD.decode(SIGNATURE).unwrap()).unwrap();
        key.verifying_key()
            .verify_strict(FINGERPRINT.as_bytes(), &sig)
            .unwrap();
        for hash in [HEX, HASH] {
            let mut alternate = nar();
            alternate.nar_hash = hash.into();
            assert_eq!(
                render_with_key("org/cache", false, &alternate, Some(("fixture-7", &key))).unwrap(),
                body
            );
        }
        let mut full_deriver = nar();
        full_deriver.deriver = Some(format!("/nix/store/{}", full_deriver.deriver.unwrap()));
        assert_eq!(
            render_with_key("org/cache", false, &full_deriver, Some(("fixture-7", &key))).unwrap(),
            body
        );
    }

    #[test]
    fn relative_urls_and_optional_fields() {
        for (path, private, url) in [
            ("cache", false, "../nar/"),
            ("org/cache", false, "../../nar/"),
            ("cache", true, "nar/"),
            ("org/cache", true, "nar/"),
        ] {
            let mut minimal = nar();
            minimal.references.clear();
            minimal.deriver = None;
            minimal.system = Some(String::new());
            minimal.signatures.clear();
            let body = render_with_key(path, private, &minimal, None).unwrap();
            assert!(body.contains(&format!("\nURL: {url}{}", minimal.file_hash)));
            for omitted in ["References:", "Deriver:", "System:", "Sig:"] {
                assert!(!body.contains(omitted));
            }
            assert!(body.ends_with("NarSize: 123456\n"));
            minimal.nar_hash = "invalid".into();
            assert!(render_with_key(path, private, &minimal, None).is_err());
        }
    }

    // Run with DATABASE_URL pointing at a disposable Postgres server. SQLx
    // creates and drops its own database; no existing cache rows are touched.
    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn render_queries_fresh_keys_and_fails_closed(pool: sqlx::PgPool) {
        sqlx::query("CREATE TABLE caches (id integer PRIMARY KEY, signing_key_name text, signing_public_key text, signing_key_sealed text)")
            .execute(&pool).await.unwrap();
        for id in [7, 8] {
            sqlx::query("INSERT INTO caches VALUES ($1, $2, $3, $4)")
                .bind(id)
                .bind("fixture-7")
                .bind(PUBLIC)
                .bind(V2)
                .execute(&pool)
                .await
                .unwrap();
        }
        let mut cfg = config();
        cfg.signing_private_key = SECRET.into();
        let expected = render(&pool, &cfg, 7, "org/cache", false, &nar())
            .await
            .unwrap();
        assert!(expected.ends_with(&format!("Sig: fixture-7:{SIGNATURE}\n")));
        // A warmed signer must observe identity changes from another publish.
        sqlx::query("UPDATE caches SET signing_key_name = 'changed' WHERE id = 7")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            render(&pool, &cfg, 7, "org/cache", false, &nar())
                .await
                .is_err()
        );
        sqlx::query("UPDATE caches SET signing_key_name = 'fixture-7', signing_key_sealed = $1 WHERE id = 7")
            .bind(V1).execute(&pool).await.unwrap();
        assert_eq!(
            render(&pool, &cfg, 7, "org/cache", false, &nar())
                .await
                .unwrap(),
            expected
        );
        assert!(
            render(&pool, &cfg, 8, "org/other", false, &nar())
                .await
                .is_err()
        );
        assert!(
            render(&pool, &cfg, 999, "missing", false, &nar())
                .await
                .is_err()
        );
        sqlx::query("UPDATE caches SET signing_key_name = NULL, signing_public_key = NULL, signing_key_sealed = NULL WHERE id = 7")
            .execute(&pool).await.unwrap();
        cfg.require_cache_signing_keys = true;
        assert!(
            render(&pool, &cfg, 7, "cache", false, &nar())
                .await
                .is_err()
        );
        cfg.require_cache_signing_keys = false;
        let shared = render(&pool, &cfg, 7, "cache", false, &nar())
            .await
            .unwrap();
        assert!(shared.ends_with(&format!("Sig: shared:{SIGNATURE}\n")));
    }
}
