//! Transparent connection faults with optional passive public chain-point observation.
use crate::chain_observer::Observer;
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs, io,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct Statistics {
    pub enabled: bool,
    pub active_connections: usize,
    pub admitted_connections: u64,
    pub rejected_connections: u64,
    pub upstream_failures: u64,
    pub worker_panics: u64,
    pub completed_upstream_bytes: u64,
    pub completed_downstream_bytes: u64,
}
struct State {
    statistics: Statistics,
    stopping: bool,
    active: BTreeMap<u64, (UnixStream, UnixStream)>,
    observer: Option<Observer>,
    upstream: PathBuf,
    generation: u64,
}
type Shared = Arc<(Mutex<State>, Condvar)>;

fn close_connections(state: &State) {
    for (client, node) in state.active.values() {
        let _ = client.shutdown(Shutdown::Both);
        let _ = node.shutdown(Shutdown::Both);
    }
}

fn copy_direction(
    mut source: UnixStream,
    mut destination: UnixStream,
    observer: Option<(Observer, u64, bool)>,
) -> io::Result<u64> {
    let result = if let Some((observer, id, upstream)) = &observer {
        (|| {
            let mut total = 0;
            let mut buffer = [0u8; 16384];
            loop {
                let count = match source.read(&mut buffer) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    break;
                }
                observer.bytes(*id, *upstream, &buffer[..count]);
                destination.write_all(&buffer[..count])?;
                total += count as u64;
            }
            Ok(total)
        })()
    } else {
        io::copy(&mut source, &mut destination)
    };
    if let Some((observer, id, upstream)) = observer {
        observer.close(id, upstream);
    }
    if result.is_ok() {
        // A client may half-close its request and still expect the complete response.
        let _ = destination.shutdown(Shutdown::Write);
    } else {
        let _ = source.shutdown(Shutdown::Both);
        let _ = destination.shutdown(Shutdown::Both);
    }
    result
}

fn relay(
    client: UnixStream,
    node: UnixStream,
    shared: &Shared,
    generation: u64,
) -> Result<JoinHandle<()>> {
    let upstream_read = client.try_clone()?;
    let upstream_write = node.try_clone()?;
    let downstream_read = node.try_clone()?;
    let downstream_write = client.try_clone()?;
    let id;
    let observer;
    {
        let mut state = shared.0.lock().unwrap();
        if !state.statistics.enabled || state.stopping || state.generation != generation {
            state.statistics.rejected_connections += 1;
            let _ = client.shutdown(Shutdown::Both);
            let _ = node.shutdown(Shutdown::Both);
            return Ok(thread::spawn(|| {}));
        }
        id = state.statistics.admitted_connections;
        state.statistics.admitted_connections += 1;
        state.active.insert(id, (client, node));
        observer = state.observer.clone();
    }
    let shared = Arc::clone(shared);
    Ok(thread::spawn(move || {
        let up_observer = observer.clone().map(|value| (value, id, true));
        let upstream =
            thread::spawn(move || copy_direction(upstream_read, upstream_write, up_observer));
        let down = copy_direction(
            downstream_read,
            downstream_write,
            observer.map(|value| (value, id, false)),
        );
        let up = upstream.join();
        let mut state = shared.0.lock().unwrap();
        if let Ok(Ok(bytes)) = up {
            state.statistics.completed_upstream_bytes += bytes;
        } else if up.is_err() {
            state.statistics.worker_panics += 1;
        }
        if let Ok(bytes) = down {
            state.statistics.completed_downstream_bytes += bytes;
        }
        state.active.remove(&id);
        shared.1.notify_all();
    }))
}

/// Owns only a newly bound socket and its accepted streams. Never logs raw payloads.
pub struct SocketProxy {
    path: PathBuf,
    inode: u64,
    shared: Shared,
    acceptor: Option<JoinHandle<()>>,
}
impl SocketProxy {
    pub fn bind(path: &Path, upstream: &Path) -> Result<Self> {
        Self::bind_inner(path, upstream, None)
    }
    /// Retain only public chain-sync points; parsing errors never rewrite or drop bytes.
    pub fn bind_observed(path: &Path, upstream: &Path, observer: Observer) -> Result<Self> {
        Self::bind_inner(path, upstream, Some(observer))
    }
    fn bind_inner(path: &Path, upstream: &Path, observer: Option<Observer>) -> Result<Self> {
        ensure!(
            path.is_absolute() && upstream.is_absolute() && path != upstream,
            "proxy requires distinct absolute socket paths"
        );
        let parent = fs::metadata(path.parent().context("proxy socket has no parent")?)?;
        ensure!(
            parent.is_dir() && parent.permissions().mode() & 0o077 == 0,
            "proxy socket parent must be private"
        );
        ensure!(
            fs::metadata(upstream)?.file_type().is_socket(),
            "upstream is not a Unix socket"
        );
        let listener = UnixListener::bind(path).context("cannot bind new owned proxy socket")?;
        let inode = fs::symlink_metadata(path)?.ino();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let shared = Arc::new((
            Mutex::new(State {
                statistics: Statistics {
                    enabled: true,
                    active_connections: 0,
                    admitted_connections: 0,
                    rejected_connections: 0,
                    upstream_failures: 0,
                    worker_panics: 0,
                    completed_upstream_bytes: 0,
                    completed_downstream_bytes: 0,
                },
                stopping: false,
                active: BTreeMap::new(),
                observer,
                upstream: upstream.to_path_buf(),
                generation: 0,
            }),
            Condvar::new(),
        ));
        let owner = Arc::clone(&shared);
        let acceptor = thread::spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            loop {
                if owner.0.lock().unwrap().stopping {
                    break;
                }
                match listener.accept() {
                    Ok((client, _)) => {
                        let mut state = owner.0.lock().unwrap();
                        if !state.statistics.enabled || state.stopping {
                            state.statistics.rejected_connections += 1;
                            let _ = client.shutdown(Shutdown::Both);
                        } else {
                            let upstream = state.upstream.clone();
                            let generation = state.generation;
                            drop(state);
                            match UnixStream::connect(&upstream).and_then(|node| {
                                relay(client, node, &owner, generation).map_err(io::Error::other)
                            }) {
                                Ok(worker) => workers.push(worker),
                                Err(_) => owner.0.lock().unwrap().statistics.upstream_failures += 1,
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => {
                        owner.0.lock().unwrap().statistics.upstream_failures += 1;
                        break;
                    }
                }
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        if workers.swap_remove(index).join().is_err() {
                            owner.0.lock().unwrap().statistics.worker_panics += 1;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            for worker in workers {
                if worker.join().is_err() {
                    owner.0.lock().unwrap().statistics.worker_panics += 1;
                }
            }
        });
        Ok(Self {
            path: path.into(),
            inode,
            shared,
            acceptor: Some(acceptor),
        })
    }

    pub fn statistics(&self) -> Statistics {
        let state = self.shared.0.lock().unwrap();
        let mut statistics = state.statistics.clone();
        statistics.active_connections = state.active.len();
        statistics
    }
    /// Attach a fresh passive observer only after all previous streams have drained.
    pub fn observe_while_paused(&self, observer: Observer) -> Result<()> {
        let mut state = self.shared.0.lock().unwrap();
        ensure!(
            !state.stopping && !state.statistics.enabled && state.active.is_empty(),
            "observer attachment requires a paused drained relay"
        );
        ensure!(state.observer.is_none(), "relay already has an observer");
        state.observer = Some(observer);
        Ok(())
    }
    /// Change the real upstream only while old streams are drained and admission is disabled.
    pub fn retarget_while_paused(&self, upstream: &Path) -> Result<()> {
        ensure!(
            upstream.is_absolute() && upstream != self.path,
            "retarget requires a distinct absolute Unix socket"
        );
        ensure!(
            fs::symlink_metadata(upstream)?.file_type().is_socket(),
            "retarget upstream is not an actual Unix socket"
        );
        let mut state = self.shared.0.lock().unwrap();
        ensure!(
            !state.stopping && !state.statistics.enabled && state.active.is_empty(),
            "retarget requires a paused drained relay"
        );
        state.upstream = upstream.to_path_buf();
        Ok(())
    }
    pub fn pause(&self, timeout: Duration) -> Result<Statistics> {
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.0.lock().unwrap();
        ensure!(!state.stopping, "proxy is stopping");
        state.statistics.enabled = false;
        state.generation = state
            .generation
            .checked_add(1)
            .context("relay generation overflow")?;
        close_connections(&state);
        while !state.active.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "proxy connections did not drain");
            state = self.shared.1.wait_timeout(state, remaining).unwrap().0;
        }
        drop(state);
        Ok(self.statistics())
    }
    pub fn resume(&self) -> Result<()> {
        let mut state = self.shared.0.lock().unwrap();
        ensure!(
            !state.stopping && state.active.is_empty(),
            "proxy is stopping or not drained"
        );
        state.statistics.enabled = true;
        Ok(())
    }
}
impl Drop for SocketProxy {
    fn drop(&mut self) {
        {
            let mut state = self.shared.0.lock().unwrap();
            state.stopping = true;
            state.statistics.enabled = false;
            close_connections(&state);
        }
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.ino() == self.inode && m.file_type().is_socket())
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Control audit only. This cannot be used as wallet conformance evidence.
pub fn audit(
    node: &crate::node::NodeOracle,
    path: &Path,
    timeout: Duration,
    output: &Path,
) -> Result<bool> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut observations = Vec::new();
    let result = (|| -> Result<()> {
        ensure!(!timeout.is_zero(), "audit timeout must be positive");
        let direct_before = node.tip(timeout)?;
        observations
            .push(serde_json::json!({"stage":"direct-before", "tip":tip_value(&direct_before)}));
        let proxy = SocketProxy::bind(path, &node.socket)?;
        let relayed = crate::node::NodeOracle {
            executable: node.executable.clone(),
            socket: path.into(),
            network_magic: node.network_magic,
        };
        let connected = matching_tip(node, &relayed, timeout)?;
        observations
            .push(serde_json::json!({"stage":"relayed-before", "tip":tip_value(&connected)}));
        let paused = proxy.pause(timeout)?;
        ensure!(
            paused.admitted_connections > 0
                && paused.active_connections == 0
                && !paused.enabled
                && paused.completed_upstream_bytes > 0
                && paused.completed_downstream_bytes > 0,
            "node audit did not observe a complete real protocol exchange"
        );
        observations.push(serde_json::json!({"stage":"paused", "statistics":paused}));
        let denied = relayed.tip(timeout.min(Duration::from_secs(2)));
        ensure!(
            denied.is_err(),
            "paused relay unexpectedly served a node query"
        );
        let blocked = proxy.statistics();
        ensure!(
            blocked.admitted_connections == paused.admitted_connections
                && blocked.rejected_connections > paused.rejected_connections
                && blocked.active_connections == 0,
            "paused query did not reach the disabled proxy or escaped its gate"
        );
        observations.push(serde_json::json!({"stage":"rejected", "error":denied.unwrap_err().to_string(), "statistics":blocked}));
        node.advancing(connected.height, timeout)?;
        let advanced = node.tip(timeout)?;
        ensure!(
            advanced.height > connected.height,
            "direct node did not advance during disconnection"
        );
        observations.push(
            serde_json::json!({"stage":"direct-during-disconnection", "tip":tip_value(&advanced)}),
        );
        proxy.resume()?;
        let reconnected = matching_tip(node, &relayed, timeout)?;
        ensure!(
            reconnected.height >= advanced.height,
            "reconnected node regressed"
        );
        let final_statistics = proxy.pause(timeout)?;
        ensure!(
            final_statistics.admitted_connections > paused.admitted_connections
                && final_statistics.upstream_failures == 0
                && final_statistics.worker_panics == 0,
            "relay did not reconnect cleanly to the real upstream"
        );
        observations.push(serde_json::json!({"stage":"reconnected", "tip":tip_value(&reconnected), "statistics":final_statistics}));
        drop(proxy);
        ensure!(!path.exists(), "owned proxy socket remained after teardown");
        let after = node.tip(timeout)?;
        ensure!(
            after.height >= reconnected.height,
            "direct node regressed after proxy teardown"
        );
        observations
            .push(serde_json::json!({"stage":"direct-after-teardown", "tip":tip_value(&after)}));
        Ok(())
    })();
    let passed = result.is_ok();
    serde_json::to_writer_pretty(
        file,
        &serde_json::json!({
            "format_version":1,"kind":"node-connection-control-audit","passed":passed,
            "count_as_conformance_evidence":false,"observations":observations,
            "error":result.err().map(|error|error.to_string()),
            "cardano_cli":node.executable,"upstream_socket":node.socket,"proxy_socket":path,
            "network_magic":node.network_magic
        }),
    )?;
    Ok(passed)
}

fn tip_value(tip: &crate::node::Tip) -> serde_json::Value {
    serde_json::json!({"height":tip.height,"slot":tip.slot,"hash":tip.hash})
}

fn matching_tip(
    direct: &crate::node::NodeOracle,
    relayed: &crate::node::NodeOracle,
    timeout: Duration,
) -> Result<crate::node::Tip> {
    let deadline = Instant::now() + timeout;
    loop {
        let before = direct.tip(deadline.saturating_duration_since(Instant::now()))?;
        let through = relayed.tip(deadline.saturating_duration_since(Instant::now()))?;
        let after = direct.tip(deadline.saturating_duration_since(Instant::now()))?;
        if [&before, &after].iter().any(|tip| {
            tip.hash == through.hash && tip.height == through.height && tip.slot == through.slot
        }) {
            return Ok(through);
        }
        ensure!(
            Instant::now() < deadline,
            "relayed node tip never matched independent samples"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn private_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn preserves_large_binary_bytes_and_half_closed_response() {
        binary_roundtrip(false);
    }
    #[test]
    fn observation_failure_still_forwards_every_binary_byte_and_half_close() {
        binary_roundtrip(true);
    }
    fn binary_roundtrip(observed: bool) {
        let root = private_fixture();
        let node = root.path().join("node.socket");
        let socket = root.path().join("proxy.socket");
        let listener = UnixListener::bind(&node).unwrap();
        let mut expected: Vec<u8> = (0..1_048_593).map(|n| (n % 251) as u8).collect();
        if observed {
            expected[..8].fill(0);
        }
        let bytes = expected.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            assert_eq!(received, bytes);
            stream.write_all(&received).unwrap();
        });
        let observer = Observer::default();
        let proxy = if observed {
            SocketProxy::bind_observed(&socket, &node, observer.clone()).unwrap()
        } else {
            SocketProxy::bind(&socket, &node).unwrap()
        };
        assert!(SocketProxy::bind(&socket, &node).is_err());
        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(&expected).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, expected);
        server.join().unwrap();
        let stats = proxy.pause(Duration::from_secs(5)).unwrap();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.completed_upstream_bytes, expected.len() as u64);
        assert_eq!(stats.completed_downstream_bytes, expected.len() as u64);
        assert_eq!(stats.upstream_failures, 0);
        if observed {
            assert!(!observer.snapshot().errors.is_empty());
        }
        drop(client);
        drop(proxy);
        assert!(!socket.exists());
        assert!(node.exists());
    }

    #[test]
    fn drains_live_connections_rejects_paused_clients_and_reconnects() {
        let root = private_fixture();
        let node = root.path().join("node.socket");
        let socket = root.path().join("proxy.socket");
        let listener = UnixListener::bind(&node).unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                io::copy(&mut stream.try_clone().unwrap(), &mut stream).unwrap();
            }
        });
        let proxy = SocketProxy::bind(&socket, &node).unwrap();
        let observer = Observer::default();
        assert!(proxy.observe_while_paused(observer.clone()).is_err());
        let mut first = UnixStream::connect(&socket).unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        first.write_all(b"before").unwrap();
        let mut bytes = [0; 6];
        first.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"before");
        assert_eq!(proxy.statistics().active_connections, 1);
        let paused = proxy.pause(Duration::from_secs(5)).unwrap();
        proxy.observe_while_paused(observer.clone()).unwrap();
        assert!(proxy.observe_while_paused(observer.clone()).is_err());
        assert!(!paused.enabled && paused.active_connections == 0);
        assert!(first.read(&mut bytes).is_ok_and(|n| n == 0));
        let mut blocked = UnixStream::connect(&socket).unwrap();
        blocked
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert!(blocked.read(&mut bytes).is_ok_and(|n| n == 0));
        assert!(proxy.statistics().rejected_connections >= 1);
        proxy.resume().unwrap();
        let mut second = UnixStream::connect(&socket).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        second.write_all(b"after!").unwrap();
        second.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"after!");
        second.shutdown(Shutdown::Write).unwrap();
        assert!(second.read(&mut bytes).is_ok_and(|n| n == 0));
        drop(second);
        server.join().unwrap();
        proxy.pause(Duration::from_secs(5)).unwrap();
        assert_eq!(proxy.statistics().admitted_connections, 2);
        assert_eq!(proxy.statistics().worker_panics, 0);
        assert_eq!(observer.snapshot().connections, 1);
    }

    #[test]
    fn cleanup_preserves_replacement_inode_and_refuses_public_parent() {
        let root = private_fixture();
        let node = root.path().join("node.socket");
        let socket = root.path().join("proxy.socket");
        let _listener = UnixListener::bind(&node).unwrap();
        let proxy = SocketProxy::bind(&socket, &node).unwrap();
        fs::remove_file(&socket).unwrap();
        fs::write(&socket, b"replacement owned elsewhere").unwrap();
        drop(proxy);
        assert_eq!(fs::read(&socket).unwrap(), b"replacement owned elsewhere");
        fs::remove_file(&socket).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SocketProxy::bind(&socket, &node).is_err());
        assert!(!socket.exists());
    }
    #[test]
    fn retarget_only_after_drain_switches_real_upstream_and_preserves_bytes() {
        let root = private_fixture();
        let a = root.path().join("a.socket");
        let b = root.path().join("b.socket");
        let socket = root.path().join("proxy.socket");
        let first = UnixListener::bind(&a).unwrap();
        let second = UnixListener::bind(&b).unwrap();
        let serve = |listener: UnixListener, label: u8| {
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).unwrap();
                stream.write_all(&[label]).unwrap();
                stream.write_all(&bytes).unwrap();
            })
        };
        let first = serve(first, b'A');
        let second = serve(second, b'B');
        let proxy = SocketProxy::bind(&socket, &a).unwrap();
        assert!(proxy.retarget_while_paused(&b).is_err());
        let exchange = || {
            let mut client = UnixStream::connect(&socket).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(b"ping").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            response
        };
        assert_eq!(exchange(), b"Aping");
        first.join().unwrap();
        proxy.pause(Duration::from_secs(5)).unwrap();
        assert!(proxy.retarget_while_paused(&socket).is_err());
        proxy.retarget_while_paused(&b).unwrap();
        proxy.resume().unwrap();
        assert_eq!(exchange(), b"Bping");
        second.join().unwrap();
        proxy.pause(Duration::from_secs(5)).unwrap();
        assert_eq!(proxy.statistics().admitted_connections, 2);
        assert_eq!(proxy.statistics().worker_panics, 0);
    }
    #[test]
    fn admission_started_before_pause_cannot_escape_into_a_later_generation() {
        let root = private_fixture();
        let node = root.path().join("node.socket");
        let socket = root.path().join("proxy.socket");
        let _listener = UnixListener::bind(&node).unwrap();
        let proxy = SocketProxy::bind(&socket, &node).unwrap();
        let old = proxy.shared.0.lock().unwrap().generation;
        proxy.pause(Duration::from_secs(5)).unwrap();
        proxy.resume().unwrap();
        let (client, mut peer) = UnixStream::pair().unwrap();
        let (upstream, mut node_peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        node_peer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        relay(client, upstream, &proxy.shared, old)
            .unwrap()
            .join()
            .unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        assert_eq!(node_peer.read(&mut byte).unwrap(), 0);
        assert_eq!(proxy.statistics().admitted_connections, 0);
        assert_eq!(proxy.statistics().rejected_connections, 1);
    }
}
