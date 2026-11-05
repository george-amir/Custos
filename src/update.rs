//! Bounded, checksum-verified executable updates. The CLI uses the official source.
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Url};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_METADATA: usize = 1024 * 1024;
pub const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    state: String,
    digest: Option<String>,
}

pub struct ReleaseUpdater {
    client: Client,
    api: Url,
    downloads: Url,
}
pub struct UpdatePlan {
    version: Version,
    url: Url,
    size: u64,
    checksum: String,
}
impl UpdatePlan {
    pub fn version(&self) -> &Version {
        &self.version
    }
}
pub enum UpdateStatus {
    Available(UpdatePlan),
    Current { installed: Version, latest: Version },
}

pub fn release_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        _ => bail!("No prebuilt updater for this platform; install with Cargo instead"),
    }
}
pub fn binary_asset_name(target: &str) -> String {
    format!(
        "custos-{target}{}",
        if target.ends_with("windows-msvc") {
            ".exe"
        } else {
            ""
        }
    )
}

fn stable_version(value: &str) -> Result<Version> {
    ensure!(value.len() <= 64, "Version is too long");
    let version = Version::parse(value.strip_prefix('v').unwrap_or(value))
        .context("Expected a version such as v0.5.0")?;
    ensure!(
        version.pre.is_empty() && version.build.is_empty(),
        "Only stable releases are supported"
    );
    Ok(version)
}

impl ReleaseUpdater {
    pub fn github() -> Result<Self> {
        Self::from_source(
            "https://api.github.com/repos/george-amir/Custos/releases/",
            "https://github.com/george-amir/Custos/releases/download/",
        )
    }

    /// Explicit trusted mirror seam for embedded applications. HTTP is allowed only
    /// for loopback fixtures; the CLI exposes no source or verification override.
    pub fn from_source(api: &str, downloads: &str) -> Result<Self> {
        let api = Url::parse(api)?;
        let downloads = Url::parse(downloads)?;
        for url in [&api, &downloads] {
            let loopback = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            ensure!(
                (url.scheme() == "https" || (url.scheme() == "http" && loopback))
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path().ends_with('/'),
                "Invalid trusted update source"
            );
        }
        let client = Client::builder()
            .https_only(api.scheme() == "https" && downloads.scheme() == "https")
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("Custos/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            client,
            api,
            downloads,
        })
    }

    pub async fn check(&self, current: &str, requested: Option<&str>) -> Result<UpdateStatus> {
        let current = stable_version(current)?;
        let requested = requested.map(stable_version).transpose()?;
        if let Some(version) = &requested {
            ensure!(
                version >= &current,
                "Refusing to downgrade; older releases may not understand the ban journal"
            );
        }
        let endpoint = requested
            .as_ref()
            .map(|v| format!("tags/v{v}"))
            .unwrap_or_else(|| "latest".into());
        let mut response = self
            .client
            .get(self.api.join(&endpoint)?)
            .header("accept", "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_METADATA as u64),
            "Release metadata exceeds byte limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= MAX_METADATA,
                "Release metadata exceeds byte limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let release: Release =
            serde_json::from_slice(&bytes).context("Invalid release metadata")?;
        ensure!(
            !release.draft && !release.prerelease && release.tag_name.starts_with('v'),
            "Expected a published stable release"
        );
        let version = stable_version(&release.tag_name)?;
        ensure!(
            requested.as_ref().is_none_or(|v| *v == version),
            "Release tag does not match the requested version"
        );
        if version <= current {
            return Ok(UpdateStatus::Current {
                installed: current,
                latest: version,
            });
        }
        ensure!(release.assets.len() <= 64, "Too many release assets");
        let name = binary_asset_name(release_target()?);
        let asset = release
            .assets
            .into_iter()
            .find(|a| a.name == name)
            .context("This release has no updater binary for this platform")?;
        ensure!(
            asset.state == "uploaded" && asset.size > 0 && asset.size <= MAX_BINARY_BYTES,
            "Invalid or oversized release binary"
        );
        let checksum = asset
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .context("Release binary has no SHA-256 digest")?;
        ensure!(
            checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid release digest"
        );
        Ok(UpdateStatus::Available(UpdatePlan {
            version: version.clone(),
            url: self.downloads.join(&format!("v{version}/{name}"))?,
            size: asset.size,
            checksum: checksum.to_ascii_lowercase(),
        }))
    }

    /// Replace only the running executable, after all checks have succeeded.
    pub async fn install(&self, plan: UpdatePlan) -> Result<Version> {
        let current = std::env::current_exe()?.canonicalize()?;
        let parent = current
            .parent()
            .context("Executable has no parent directory")?;
        let directory = tempfile::Builder::new().prefix(".custos-update-").tempdir_in(parent)
            .context("Cannot write the executable directory; use sudo/Administrator for a system installation")?;
        let candidate = directory.path().join(if cfg!(windows) {
            "custos.exe"
        } else {
            "custos"
        });
        let mut response = self.client.get(plan.url).send().await?.error_for_status()?;
        ensure!(
            response.content_length().is_none_or(|n| n == plan.size),
            "Binary size differs from release metadata"
        );
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await? {
            size = size
                .checked_add(chunk.len() as u64)
                .context("Binary size overflow")?;
            ensure!(
                size <= plan.size && size <= MAX_BINARY_BYTES,
                "Binary exceeds byte limit"
            );
            hash.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        ensure!(
            size == plan.size && format!("{:x}", hash.finalize()) == plan.checksum,
            "Binary checksum/size verification failed; current installation is unchanged"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o755)).await?;
        }
        verify_version(&candidate, &plan.version).await?;
        let version = plan.version;
        tokio::task::spawn_blocking(move || replace_current(&current, &candidate, directory))
            .await??;
        Ok(version)
    }
}

async fn verify_version(candidate: &Path, expected: &Version) -> Result<()> {
    let mut child = tokio::process::Command::new(candidate)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("Downloaded binary cannot run on this host; current installation is unchanged")?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .context("Missing version output")?
            .take(1025)
            .read_to_end(&mut output)
            .await?;
        ensure!(
            output.len() <= 1024 && child.wait().await?.success(),
            "Candidate version check failed"
        );
        ensure!(
            std::str::from_utf8(&output)?.trim() == format!("custos {expected}"),
            "Candidate version does not match the release"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(()),
        error => {
            let _ = child.kill().await;
            bail!("Candidate validation failed; current installation is unchanged: {error:?}");
        }
    }
}

fn replace_current(current: &Path, candidate: &Path, directory: tempfile::TempDir) -> Result<()> {
    let backup = directory.path().join("previous-binary");
    std::fs::copy(current, &backup).context("Could not preserve the current binary")?;
    // Windows FlushFileBuffers requires a handle opened for writing.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&backup)?
        .sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(current)?.permissions().mode() & 0o777;
        std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(mode))?;
    }
    if let Err(error) = self_replace::self_replace(candidate) {
        if !current.exists()
            && let Err(restore) = std::fs::rename(&backup, current)
        {
            let retained: PathBuf = directory.keep();
            bail!(
                "Update failed ({error}); restore failed ({restore}); original binary retained at {}",
                retained.join("previous-binary").display()
            );
        }
        return Err(error).context("Executable replacement failed; original installation retained");
    }
    #[cfg(unix)]
    std::fs::File::open(current.parent().context("Missing executable parent")?)?.sync_all()?;
    Ok(())
}
