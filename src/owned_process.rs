//! Process controls for wallet lifecycle tests. These never adopt supplied PIDs.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn listener(target: &str) -> Result<SocketAddr> {
    let url = reqwest::Url::parse(target)?;
    ensure!(
        url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/v2/",
        "owned target must be an explicit loopback HTTP /v2/ URL"
    );
    let address: IpAddr = url
        .host_str()
        .context("target has no host")?
        .trim_matches(['[', ']'])
        .parse()?;
    ensure!(address.is_loopback(), "owned target must be loopback");
    Ok(SocketAddr::new(
        address,
        url.port().context("owned target requires explicit port")?,
    ))
}

/// Refuse to adopt a listening service before creating any owned state.
pub fn require_unused_listener(target: &str) -> Result<()> {
    match TcpStream::connect_timeout(&listener(target)?, Duration::from_millis(200)) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
        _ => anyhow::bail!("owned wallet target is already listening or cannot be proven unused"),
    }
}

/// The executable must remain a foreground process; database placeholders are whole values.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("cannot create fresh private lifecycle directory")
}

fn private_log(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// Only this object's directly spawned foreground child is ever terminated.
/// Logs and database survive cleanup for inspection; they may contain private material.
pub struct WalletProcess {
    launch: Launch,
    workspace: PathBuf,
    database: String,
    executable_sha256: String,
    generation: u32,
    child: Option<Child>,
}

impl WalletProcess {
    /// Only listener startup is retryable here; HTTP schemas/statuses are checked by the live suite.
    pub fn wait_listener(&mut self, target: &str, timeout: Duration) -> Result<()> {
        let address = listener(target)?;
        let deadline = Instant::now() + timeout;
        loop {
            self.ensure_running()?;
            match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
                Ok(_) => {
                    self.ensure_running()?;
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(error.into()),
            }
            ensure!(
                Instant::now() < deadline,
                "owned wallet listener did not start"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    pub fn start(launch: Launch, workspace: &Path) -> Result<Self> {
        ensure!(
            launch.executable.is_absolute(),
            "wallet executable must be absolute"
        );
        ensure!(
            launch.executable.is_file(),
            "wallet executable is not a file"
        );
        ensure!(
            workspace.is_absolute(),
            "lifecycle workspace must be absolute"
        );
        let values = launch.arguments.iter().chain(launch.environment.values());
        let mut placeholders = 0;
        for value in values {
            if value == "{database}" {
                placeholders += 1;
            } else {
                ensure!(
                    !value.contains("{database}"),
                    "database placeholder must be a complete value"
                );
            }
        }
        ensure!(
            placeholders == 1,
            "launch must contain exactly one database placeholder"
        );
        let executable_sha256 = digest(&launch.executable)?;
        // Exclusive creation refuses existing workspaces, including symlinks.
        private_directory(workspace)?;
        let database = workspace.join("database");
        private_directory(&database)?;
        let mut owned = Self {
            launch,
            workspace: workspace.into(),
            database: database.to_str().context("non-UTF8 database path")?.into(),
            executable_sha256,
            generation: 0,
            child: None,
        };
        owned.spawn()?;
        Ok(owned)
    }

    fn spawn(&mut self) -> Result<()> {
        ensure!(self.child.is_none(), "owned wallet is already running");
        let stdout = private_log(
            &self
                .workspace
                .join(format!("wallet-{}.stdout", self.generation)),
        )?;
        let stderr = private_log(
            &self
                .workspace
                .join(format!("wallet-{}.stderr", self.generation)),
        )?;
        let expand = |value: &String| {
            if value == "{database}" {
                self.database.clone()
            } else {
                value.clone()
            }
        };
        self.child = Some(
            Command::new(&self.launch.executable)
                .args(self.launch.arguments.iter().map(expand))
                .envs(
                    self.launch
                        .environment
                        .iter()
                        .map(|(key, value)| (key, expand(value))),
                )
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .context("cannot spawn owned wallet")?,
        );
        Ok(())
    }

    pub fn ensure_running(&mut self) -> Result<u32> {
        let child = self.child.as_mut().context("owned wallet has no child")?;
        ensure!(
            child.try_wait()?.is_none(),
            "owned wallet exited unexpectedly"
        );
        Ok(child.id())
    }

    /// Crash the live owned child, reap it, then restart the same executable/database.
    pub fn crash_restart(&mut self) -> Result<()> {
        self.ensure_running()?;
        ensure!(
            digest(&self.launch.executable)? == self.executable_sha256,
            "wallet executable changed before restart"
        );
        self.stop()?;
        self.restart_stopped()
    }

    /// Restart this previously stopped/reaped owned process after an offline interval.
    pub fn restart_stopped(&mut self) -> Result<()> {
        ensure!(
            self.child.is_none(),
            "owned wallet must be stopped before delayed restart"
        );
        ensure!(
            digest(&self.launch.executable)? == self.executable_sha256,
            "wallet executable changed while stopped"
        );
        self.generation = self
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        self.spawn()
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none() {
                // Child::kill addresses the still-owned process handle, never an adopted PID.
                if let Err(error) = child.kill() {
                    // A live handle remains owned if termination failed; Drop can retry.
                    if child.try_wait()?.is_none() {
                        return Err(error.into());
                    }
                }
            }
            child.wait()?;
            self.child.take();
        }
        Ok(())
    }

    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

impl Drop for WalletProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Reserve a real loopback port without listening. Keep the descriptor alive:
/// connect is refused, but parallel tests cannot acquire the same port.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn reserved_loopback() -> Result<(std::os::fd::OwnedFd, SocketAddr)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: the standard IPv4 stream domain/type and no protocol override.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    ensure!(raw >= 0, "cannot create reserved test socket");
    // SAFETY: the successful call returned a newly owned descriptor.
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is a valid initial sockaddr_in; required fields are set below.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: a correctly sized live IPv4 address and owned socket descriptor.
    ensure!(
        unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_in).cast(),
                length,
            )
        } == 0,
        "cannot bind reserved test socket"
    );
    // SAFETY: address and length are writable storage of the advertised size.
    ensure!(
        unsafe {
            libc::getsockname(
                socket.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut length,
            )
        } == 0,
        "cannot read reserved test socket"
    );
    Ok((
        socket,
        SocketAddr::from(([127, 0, 0, 1], u16::from_be(address.sin_port))),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn listener_controls_refuse_remote_or_existing_services() {
        for target in [
            "http://192.0.2.1:18790/v2/",
            "https://127.0.0.1:18790/v2/",
            "http://127.0.0.1/v2/",
            "http://user@127.0.0.1:18790/v2/",
            "http://127.0.0.1:18790/v2/?q=1",
        ] {
            assert!(listener(target).is_err());
        }
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!("http://{}/v2/", bound.local_addr().unwrap());
        assert!(require_unused_listener(&target).is_err());
        drop(bound);
        #[cfg(target_os = "linux")]
        {
            let (_reservation, address) = reserved_loopback().unwrap();
            assert!(std::net::TcpListener::bind(address).is_err());
            require_unused_listener(&format!("http://{address}/v2/")).unwrap();
        }
        #[cfg(not(target_os = "linux"))]
        require_unused_listener(&target).unwrap();
    }

    // A real foreground subprocess fixture. It owns no grandchildren or network sockets.
    #[test]
    fn fixture() {
        if let Ok(database) = std::env::var("WC_OWNED_PROCESS_FIXTURE_DATABASE") {
            use std::io::Write;
            let path = Path::new(&database).join("persisted-generations");
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            writeln!(file, "{}", std::process::id()).unwrap();
            file.sync_all().unwrap();
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn launch() -> Launch {
        Launch {
            executable: std::env::current_exe().unwrap(),
            arguments: vec![
                "--exact".into(),
                "owned_process::tests::fixture".into(),
                "--nocapture".into(),
            ],
            environment: BTreeMap::from([(
                "WC_OWNED_PROCESS_FIXTURE_DATABASE".into(),
                "{database}".into(),
            )]),
        }
    }

    fn wait_generations(
        process: &mut WalletProcess,
        workspace: &Path,
        expected: usize,
    ) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            process.ensure_running().unwrap();
            if let Ok(value) = fs::read_to_string(workspace.join("database/persisted-generations"))
            {
                let lines: Vec<String> = value.lines().map(str::to_owned).collect();
                if lines.len() == expected {
                    return lines;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not persist its generation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn crash_reuses_database_and_reaps_only_owned_child() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("owned");
        let mut process = WalletProcess::start(launch(), &workspace).unwrap();
        let first = process.ensure_running().unwrap();
        assert_eq!(
            wait_generations(&mut process, &workspace, 1),
            [first.to_string()]
        );
        let identity = process.executable_sha256().to_string();
        process.crash_restart().unwrap();
        let second = process.ensure_running().unwrap();
        assert_ne!(first, second);
        assert_eq!(
            wait_generations(&mut process, &workspace, 2),
            [first.to_string(), second.to_string()]
        );
        assert_eq!(process.generation(), 1);
        assert_eq!(process.executable_sha256(), identity);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{first}")).exists());
        process.stop().unwrap();
        process.stop().unwrap();
        assert!(process.ensure_running().is_err());
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{second}")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&workspace).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(workspace.join("wallet-0.stdout"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn delayed_restart_preserves_database_and_refuses_a_running_child() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("owned");
        let mut process = WalletProcess::start(launch(), &workspace).unwrap();
        let old = process.ensure_running().unwrap();
        wait_generations(&mut process, &workspace, 1);
        assert!(process.restart_stopped().is_err());
        assert_eq!(process.ensure_running().unwrap(), old);
        process.stop().unwrap();
        assert!(process.ensure_running().is_err());
        fs::write(
            workspace.join("database/offline-marker"),
            b"preserve-during-offline-chain-advance",
        )
        .unwrap();
        process.restart_stopped().unwrap();
        let new = process.ensure_running().unwrap();
        assert_ne!(old, new);
        assert_eq!(
            wait_generations(&mut process, &workspace, 2),
            [old.to_string(), new.to_string()]
        );
        assert_eq!(
            fs::read(workspace.join("database/offline-marker")).unwrap(),
            b"preserve-during-offline-chain-advance"
        );
        assert_eq!(process.generation(), 1);
        process.stop().unwrap();
    }

    #[test]
    fn rejects_adoption_and_ambiguous_database_placeholders() {
        let root = tempfile::tempdir().unwrap();
        assert!(WalletProcess::start(launch(), root.path()).is_err());
        let workspace = root.path().join("owned");
        for value in ["no-placeholder", "--database={database}"] {
            let mut config = launch();
            config
                .environment
                .insert("WC_OWNED_PROCESS_FIXTURE_DATABASE".into(), value.into());
            assert!(WalletProcess::start(config, &workspace).is_err());
            assert!(!workspace.exists());
        }
        let mut config = launch();
        config.arguments.push("{database}".into());
        assert!(WalletProcess::start(config, &workspace).is_err());
        assert!(!workspace.exists());
    }

    #[test]
    fn drop_reaps_running_fixture_and_preserves_private_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("owned");
        let mut process = WalletProcess::start(launch(), &workspace).unwrap();
        let pid = process.ensure_running().unwrap();
        wait_generations(&mut process, &workspace, 1);
        drop(process);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(workspace.join("database/persisted-generations").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn changed_executable_refuses_restart_without_killing_the_live_child() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("wallet-executable");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut config = launch();
        config.executable = executable.clone();
        let workspace = root.path().join("owned");
        let mut process = WalletProcess::start(config, &workspace).unwrap();
        let pid = process.ensure_running().unwrap();
        wait_generations(&mut process, &workspace, 1);
        fs::remove_file(&executable).unwrap();
        fs::write(&executable, b"replacement executable").unwrap();
        assert!(process.crash_restart().is_err());
        assert_eq!(process.ensure_running().unwrap(), pid);
        assert_eq!(process.generation(), 0);
        assert!(!workspace.join("wallet-1.stdout").exists());
        process.stop().unwrap();
    }
}
