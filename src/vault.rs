use crate::model::{Credential, Metadata, valid_name};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Record {
    version: u32,
    metadata: Metadata,
    protected: String,
}

pub struct Vault {
    root: PathBuf,
    _lock: File,
}

impl Vault {
    pub fn open(root: Option<&Path>) -> Result<Self> {
        let root = match root {
            Some(path) => path.to_owned(),
            None => directories::ProjectDirs::from("", "", "agent-creds")
                .context("cannot locate local application directory")?
                .data_local_dir()
                .to_owned(),
        };
        ensure!(
            !root.is_symlink(),
            "vault directory must not be a symbolic link"
        );
        fs::create_dir_all(&root).context("cannot create vault directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = root.join("vault.lock");
        ensure!(
            !lock_path.is_symlink(),
            "vault lock must not be a symbolic link"
        );
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .context("cannot open vault lock")?;
        lock.try_lock_exclusive()
            .context("vault is busy; retry when the other operation finishes")?;
        Ok(Self { root, _lock: lock })
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        valid_name(name)?;
        let path = self.root.join(format!("{name}.json"));
        ensure!(
            !path.is_symlink(),
            "vault entry must not be a symbolic link"
        );
        Ok(path)
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.path(name)?.exists())
    }

    pub fn validate_source(&self, path: &Path) -> Result<()> {
        ensure!(
            !path
                .canonicalize()
                .context("cannot resolve source file")?
                .starts_with(self.root.canonicalize()?),
            "source file must be outside the vault"
        );
        Ok(())
    }

    fn record(&self, name: &str) -> Result<Record> {
        let data = read_bounded(&self.path(name)?)?;
        let record: Record =
            serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("invalid vault entry"))?;
        ensure!(
            record.version == 1 && record.metadata.name == name,
            "unsupported or mismatched vault entry"
        );
        Ok(record)
    }

    pub fn metadata(&self, name: &str) -> Result<Metadata> {
        Ok(self.record(name)?.metadata)
    }

    pub fn list(&self) -> Result<Vec<Metadata>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let name = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .context("invalid vault filename")?;
                records.push(self.metadata(name)?);
            }
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    pub fn load(&self, name: &str) -> Result<(Metadata, Credential)> {
        let record = self.record(name)?;
        let ciphertext = STANDARD
            .decode(&record.protected)
            .context("invalid protected data")?;
        let plaintext = Zeroizing::new(unprotect(&ciphertext, &self.root)?);
        // Bind security-relevant metadata to the encrypted payload. Editing the
        // public expiry or env can never change what exec actually uses.
        let (trusted, credential): (Metadata, Credential) = serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("invalid decrypted entry"))?;
        ensure!(
            serde_json::to_vec(&trusted)? == serde_json::to_vec(&record.metadata)?,
            "vault metadata does not match protected entry"
        );
        Ok((trusted, credential))
    }

    pub fn save(&self, metadata: &Metadata, credential: &Credential, replace: bool) -> Result<()> {
        let path = self.path(&metadata.name)?;
        ensure!(
            replace || !path.exists(),
            "entry already exists; use --replace explicitly"
        );
        let plaintext = Zeroizing::new(serde_json::to_vec(&(metadata, credential))?);
        ensure!(
            plaintext.len() <= 2 * 1024 * 1024,
            "credential exceeds 2 MiB protected payload limit"
        );
        let record = Record {
            version: 1,
            metadata: metadata.clone(),
            protected: STANDARD.encode(protect(&plaintext, &self.root)?),
        };
        let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
        temp.write_all(&serde_json::to_vec_pretty(&record)?)?;
        temp.as_file().sync_all()?;
        if replace {
            temp.persist(&path)
                .map_err(|_| anyhow::anyhow!("cannot atomically replace vault entry"))?;
        } else {
            temp.persist_noclobber(&path)
                .map_err(|_| anyhow::anyhow!("cannot create vault entry"))?;
        }
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        fs::remove_file(self.path(name)?).context("cannot remove entry")?;
        Ok(())
    }
}

pub fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(!path.is_symlink(), "input must not be a symbolic link");
    let file = File::open(path).context("cannot open input file")?;
    ensure!(file.metadata()?.is_file(), "input must be a regular file");
    ensure!(file.metadata()?.len() <= LIMIT, "input exceeds 4 MiB limit");
    let mut data = Zeroizing::new(Vec::new());
    file.take(LIMIT + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= LIMIT, "input exceeds 4 MiB limit");
    Ok(data)
}

pub fn remove_source(path: &Path) -> Result<()> {
    ensure!(!path.is_symlink(), "source must not be a symbolic link");
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .context("credential saved, but source could not be opened for removal")?;
    let len = file.metadata()?.len();
    ensure!(
        len <= LIMIT,
        "credential saved, but source changed; source retained"
    );
    let zeros = [0u8; 8192];
    let mut left = len;
    while left > 0 {
        let count = left.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..count])?;
        left -= count as u64;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path).context("credential saved, but source could not be removed")?;
    Ok(())
}

#[cfg(windows)]
fn crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len().try_into()?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // DPAPI allocates output with LocalAlloc; always free it after copying.
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    ensure!(success != 0, "OS credential protection failed");
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}
#[cfg(windows)]
fn protect(data: &[u8], _root: &Path) -> Result<Vec<u8>> {
    crypt(data, true)
}
#[cfg(windows)]
fn unprotect(data: &[u8], _root: &Path) -> Result<Vec<u8>> {
    crypt(data, false)
}

#[cfg(not(windows))]
fn master_key(create: bool, root: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let identity = STANDARD.encode(Sha256::digest(
        root.canonicalize()?.as_os_str().as_encoded_bytes(),
    ));
    let entry = keyring::Entry::new("agent-creds", &format!("vault-master-v1-{identity}"))
        .map_err(|_| anyhow::anyhow!("OS keyring unavailable"))?;
    let encoded = match entry.get_password() {
        Ok(value) => Zeroizing::new(value),
        Err(keyring::Error::NoEntry) if create => {
            let mut bytes = Zeroizing::new(vec![0u8; 32]);
            rand::thread_rng().fill_bytes(&mut bytes);
            let value = Zeroizing::new(STANDARD.encode(&bytes));
            entry
                .set_password(&value)
                .map_err(|_| anyhow::anyhow!("cannot save OS keyring key"))?;
            value
        }
        _ => anyhow::bail!("OS keyring unavailable or vault key missing; no plaintext fallback"),
    };
    let key = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .context("invalid keyring key")?,
    );
    ensure!(key.len() == 32, "invalid keyring key length");
    Ok(key)
}
#[cfg(not(windows))]
fn protect(data: &[u8], root: &Path) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, AeadCore, OsRng},
    };
    let key = master_key(true, root)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow::anyhow!("invalid vault key"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut result = nonce.to_vec();
    result.extend(
        cipher
            .encrypt(&nonce, data)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?,
    );
    Ok(result)
}
#[cfg(not(windows))]
fn unprotect(data: &[u8], root: &Path) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    ensure!(data.len() >= 28, "invalid protected data");
    let key = master_key(false, root)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow::anyhow!("invalid vault key"))?;
    cipher
        .decrypt(data[..12].into(), &data[12..])
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}
