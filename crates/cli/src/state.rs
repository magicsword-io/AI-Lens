use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub output: PathBuf,
    pub rules: PathBuf,
    pub capture_content: bool,
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

pub fn output_path(path: &Path) -> Result<PathBuf> {
    let path = absolute(path)?;
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }
    let parent = path.parent().context("output has no parent")?;
    let name = path.file_name().context("output has no filename")?;
    Ok(fs::canonicalize(parent)
        .context("output parent must exist")?
        .join(name))
}

pub fn private_file(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

pub fn lock(file: &File) -> Result<()> {
    let started = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(e)
                if e.raw_os_error() == fs2::lock_contended_error().raw_os_error()
                    && started.elapsed() < Duration::from_secs(2) =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e).context("cannot acquire file lock within two seconds"),
        }
    }
}

pub struct State {
    pub dir: PathBuf,
    _lock: File,
}
impl State {
    pub fn open(dir: &Path) -> Result<Self> {
        let dir = absolute(dir)?;
        if !dir.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir)?;
        }
        let dir = fs::canonicalize(dir)?;
        let file = private_file(&dir.join("control.lock"))?;
        lock(&file)?;
        Ok(Self { dir, _lock: file })
    }
    pub fn config(&self) -> Result<Option<Config>> {
        let path = self.dir.join("config.json");
        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > 65536 {
                    bail!("state config too large");
                }
                Ok(Some(
                    serde_json::from_slice(&bytes).context("invalid state config")?,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn write(&self, config: &Config) -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new_in(&self.dir)?;
        serde_json::to_writer(&mut temp, config)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        temp.persist(self.dir.join("config.json"))
            .context("cannot commit state")?;
        Ok(())
    }
}

pub fn append(path: &Path, event: &Value) -> Result<()> {
    let mut file = private_file(path).context("cannot open telemetry output")?;
    lock(&file)?;
    use std::io::{Read, Seek, SeekFrom};
    let len = file.metadata()?.len();
    if len > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last != *b"\n" {
            bail!("telemetry output has an incomplete final record; choose a new output file");
        }
    }
    file.seek(SeekFrom::End(0))?;
    let mut bytes = serde_json::to_vec(event)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_data()?;
    Ok(())
}
