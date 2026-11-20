//! Opening repository paths beneath an already opened directory, never following links.
//!
//! On Unix each component is opened with `openat(..., O_NOFOLLOW)` relative to the
//! directory handle opened before it, so a component replaced by a link at any moment is
//! refused instead of followed. Elsewhere (Windows) the standard library offers no such
//! call: every component is checked with `symlink_metadata` before use, which leaves a
//! window between the check and the open (documented in docs/THINKING_HEAD.md).
use anyhow::{Context, Result, anyhow, ensure};
use std::path::{Path, PathBuf};

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// An opened directory, the root of every path opened through it.
pub struct Dir {
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

#[cfg(unix)]
mod sys {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn cstr(name: &str) -> std::io::Result<CString> {
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }

    pub fn open_path_dir(path: &Path) -> std::io::Result<OwnedFd> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn openat(dir: &OwnedFd, name: &str, flags: i32, mode: u32) -> std::io::Result<OwnedFd> {
        let c = cstr(name)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn list(dir: &OwnedFd) -> std::io::Result<Vec<String>> {
        let copy = unsafe { libc::dup(dir.as_raw_fd()) };
        if copy < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(copy) };
        if stream.is_null() {
            unsafe { libc::close(copy) };
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::rewinddir(stream) };
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if let Ok(name) = name.to_str()
                && name != "."
                && name != ".."
            {
                names.push(name.to_string());
            }
        }
        unsafe { libc::closedir(stream) };
        names.sort();
        Ok(names)
    }

    pub fn renameat(dir: &OwnedFd, from: &str, to: &str) -> std::io::Result<()> {
        let (a, b) = (cstr(from)?, cstr(to)?);
        let r = unsafe { libc::renameat(dir.as_raw_fd(), a.as_ptr(), dir.as_raw_fd(), b.as_ptr()) };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn unlinkat(dir: &OwnedFd, name: &str) -> std::io::Result<()> {
        let c = cstr(name)?;
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn fsync(fd: &OwnedFd) -> std::io::Result<()> {
        if unsafe { libc::fsync(fd.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(unix))]
fn checked_component(path: &Path) -> Result<std::fs::Metadata> {
    let meta = std::fs::symlink_metadata(path)?;
    let reparse = {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            meta.file_attributes() & 0x400 != 0
        }
        #[cfg(not(windows))]
        {
            false
        }
    };
    ensure!(
        !meta.file_type().is_symlink() && !reparse,
        "lien refusé : {}",
        path.display()
    );
    Ok(meta)
}

impl Dir {
    /// Open a directory given by a canonical path. Its last component must not be a link.
    pub fn open_root(path: &Path) -> Result<Dir> {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("dossier introuvable : {}", path.display()))?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "dossier ordinaire requis : {}",
            path.display()
        );
        #[cfg(unix)]
        {
            let fd = sys::open_path_dir(path)
                .with_context(|| format!("ouverture impossible : {}", path.display()))?;
            Ok(Dir {
                path: path.to_path_buf(),
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            checked_component(path)?;
            Ok(Dir {
                path: path.to_path_buf(),
            })
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A subdirectory, opened without following a link.
    pub fn sub(&self, name: &str) -> Result<Dir> {
        ensure!(valid_name(name), "nom invalide : {name}");
        let path = self.path.join(name);
        #[cfg(unix)]
        {
            let fd = sys::openat(&self.fd, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .with_context(|| {
                    format!(
                        "{} : dossier ordinaire requis (lien refusé)",
                        path.display()
                    )
                })?;
            Ok(Dir { path, fd })
        }
        #[cfg(not(unix))]
        {
            let meta = checked_component(&path)?;
            ensure!(
                meta.is_dir(),
                "dossier ordinaire requis : {}",
                path.display()
            );
            Ok(Dir { path })
        }
    }

    /// Whether `name` exists here (without following a link).
    pub fn exists(&self, name: &str) -> bool {
        std::fs::symlink_metadata(self.path.join(name)).is_ok()
    }

    /// Read a regular file of at most `limit` bytes; None when it does not exist.
    pub fn read_opt(&self, name: &str, limit: u64) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        ensure!(valid_name(name), "nom invalide : {name}");
        #[cfg(unix)]
        let file = match sys::openat(&self.fd, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(fd) => std::fs::File::from(fd),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow!(
                    "{} : fichier ordinaire requis (lien refusé) : {e}",
                    self.path.join(name).display()
                ));
            }
        };
        #[cfg(not(unix))]
        let file = {
            let path = self.path.join(name);
            match checked_component(&path) {
                Ok(_) => std::fs::File::open(&path)?,
                Err(_) if !path.exists() => return Ok(None),
                Err(e) => return Err(e),
            }
        };
        ensure!(
            file.metadata()?.is_file(),
            "{} : fichier ordinaire requis",
            self.path.join(name).display()
        );
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "{} : plus de {limit} octets",
            self.path.join(name).display()
        );
        Ok(Some(bytes))
    }

    pub fn read(&self, name: &str, limit: u64) -> Result<Vec<u8>> {
        self.read_opt(name, limit)?
            .ok_or_else(|| anyhow!("fichier absent : {}", self.path.join(name).display()))
    }

    /// Names of the entries of this directory, sorted.
    pub fn list(&self) -> Result<Vec<String>> {
        #[cfg(unix)]
        {
            Ok(sys::list(&self.fd)?)
        }
        #[cfg(not(unix))]
        {
            let mut names: Vec<String> = std::fs::read_dir(&self.path)?
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .collect();
            names.sort();
            Ok(names)
        }
    }

    /// Replace `name` atomically: a temporary file in this directory, synced, renamed over
    /// the name, then the directory synced.
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        ensure!(valid_name(name), "nom invalide : {name}");
        let temporary = format!(".{name}.{}.tmp", hex::encode(rand::random::<[u8; 6]>()));
        #[cfg(unix)]
        {
            let fd = sys::openat(
                &self.fd,
                &temporary,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o644,
            )?;
            let mut file = std::fs::File::from(fd);
            let written = file.write_all(bytes).and_then(|_| file.sync_all());
            if let Err(e) = written.and_then(|_| sys::renameat(&self.fd, &temporary, name)) {
                let _ = sys::unlinkat(&self.fd, &temporary);
                return Err(e.into());
            }
            sys::fsync(&self.fd)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let tmp = self.path.join(&temporary);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if let Some(meta) = std::fs::symlink_metadata(self.path.join(name)).ok() {
                ensure!(!meta.file_type().is_symlink(), "lien refusé");
            }
            if let Err(e) = std::fs::rename(&tmp, self.path.join(name)) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
            Ok(())
        }
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        ensure!(valid_name(name), "nom invalide : {name}");
        #[cfg(unix)]
        {
            sys::unlinkat(&self.fd, name)?;
            sys::fsync(&self.fd)?;
        }
        #[cfg(not(unix))]
        std::fs::remove_file(self.path.join(name))?;
        Ok(())
    }

    /// Make renames and removals in this directory durable (no-op where unsupported).
    pub fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        sys::fsync(&self.fd)?;
        Ok(())
    }
}

/// Sync a directory given by path (Unix; no-op elsewhere).
pub fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let fd = sys::open_path_dir(path)?;
        sys::fsync(&fd)?;
    }
    let _ = path;
    Ok(())
}
