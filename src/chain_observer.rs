//! Passive, bounded observation of public node-to-client chain-sync points.
//! Based on network-mux0.11.0.0 and ouroboros-network1.2.0.0 codecs.
//! This module never manufactures a message, retains a block or changes a byte.
use anyhow::{ensure, Context, Result};
use minicbor::{data::Type, Decoder};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const STREAM_LIMIT: usize = 8 * 1024 * 1024;
const EVENT_LIMIT: usize = 4096;
const CONNECTION_LIMIT: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Point {
    Origin,
    Block { slot: u64, hash: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tip {
    pub point: Point,
    pub height: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Offered { points: Vec<Point> },
    Accepted { point: Point, tip: Tip },
    NotFound { tip: Tip },
    RolledBack { point: Point, tip: Tip },
}
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub connection: u64,
    pub event: Event,
}
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub observations: Vec<Observation>,
    pub errors: Vec<String>,
    pub connections: usize,
}

fn point(d: &mut Decoder<'_>) -> Result<Point> {
    match d.array()? {
        Some(0) => Ok(Point::Origin),
        Some(2) => {
            let slot = d.u64()?;
            let hash = d.bytes()?;
            ensure!(hash.len() == 32, "chain point hash must be32bytes");
            Ok(Point::Block {
                slot,
                hash: hex::encode(hash),
            })
        }
        _ => anyhow::bail!("invalid chain point array"),
    }
}
fn tip(d: &mut Decoder<'_>) -> Result<Tip> {
    ensure!(d.array()? == Some(2), "invalid chain tip array");
    let point = point(d)?;
    let height = d.u64()?;
    if point == Point::Origin {
        ensure!(height == 0, "origin tip has a nonzero height");
        Ok(Tip {
            point,
            height: None,
        })
    } else {
        Ok(Tip {
            point,
            height: Some(height),
        })
    }
}
fn points(d: &mut Decoder<'_>) -> Result<Vec<Point>> {
    let count = d.array()?;
    if let Some(count) = count {
        ensure!(count <= 128, "too many offered chain points");
    }
    let mut result = Vec::new();
    loop {
        if count == Some(result.len() as u64) {
            break;
        }
        if count.is_none() && d.datatype()? == Type::Break {
            d.skip()?;
            break;
        }
        ensure!(result.len() < 128, "too many offered chain points");
        result.push(point(d)?);
    }
    Ok(result)
}
fn message(bytes: &[u8], upstream: bool) -> Result<Option<Event>> {
    let mut d = Decoder::new(bytes);
    let count = d.array()?.context("indefinite chain-sync message")?;
    let kind = d.u8()?;
    let event = match (upstream, kind, count) {
        (true, 4, 2) => Some(Event::Offered {
            points: points(&mut d)?,
        }),
        (false, 5, 3) => Some(Event::Accepted {
            point: point(&mut d)?,
            tip: tip(&mut d)?,
        }),
        (false, 6, 2) => Some(Event::NotFound { tip: tip(&mut d)? }),
        (false, 3, 3) => Some(Event::RolledBack {
            point: point(&mut d)?,
            tip: tip(&mut d)?,
        }),
        (true, 0 | 7, 1) | (false, 1, 1) => None,
        (false, 2, 3) => {
            d.skip()?;
            let _ = tip(&mut d)?;
            None
        }
        _ => anyhow::bail!("unexpected chain-sync message role/tag/length"),
    };
    ensure!(d.position() == bytes.len(), "trailing chain-sync bytes");
    Ok(event)
}
#[derive(Default)]
struct Stream {
    mux: Vec<u8>,
    chain: Vec<u8>,
    closed: bool,
}
impl Stream {
    fn push(&mut self, bytes: &[u8], upstream: bool) -> Result<Vec<Event>> {
        ensure!(!self.closed, "bytes after observed stream closure");
        ensure!(
            self.mux
                .len()
                .checked_add(bytes.len())
                .is_some_and(|n| n <= STREAM_LIMIT),
            "mux observation buffer overflow"
        );
        self.mux.extend_from_slice(bytes);
        let mut consumed = 0;
        let mut events = Vec::new();
        while self.mux.len() - consumed >= 8 {
            let header = &self.mux[consumed..consumed + 8];
            let number = u16::from_be_bytes([header[4], header[5]]);
            let length = usize::from(u16::from_be_bytes([header[6], header[7]]));
            ensure!(length > 0, "zero-length mux payload");
            if self.mux.len() - consumed < 8 + length {
                break;
            }
            if number & 0x7fff == 5 {
                ensure!(
                    (number & 0x8000 == 0) == upstream,
                    "chain-sync mux direction differs"
                );
                ensure!(
                    self.chain
                        .len()
                        .checked_add(length)
                        .is_some_and(|n| n <= STREAM_LIMIT),
                    "chain-sync observation buffer overflow"
                );
                self.chain
                    .extend_from_slice(&self.mux[consumed + 8..consumed + 8 + length]);
                let mut read = 0;
                while read < self.chain.len() {
                    let mut decoder = Decoder::new(&self.chain[read..]);
                    match decoder.skip() {
                        Ok(()) => {
                            let end = read + decoder.position();
                            if let Some(event) = message(&self.chain[read..end], upstream)? {
                                events.push(event);
                            }
                            ensure!(events.len() <= EVENT_LIMIT, "too many chain-sync events");
                            read = end;
                        }
                        Err(error) if error.is_end_of_input() => break,
                        Err(_) => anyhow::bail!("invalid chain-sync CBOR framing"),
                    }
                }
                self.chain.drain(..read);
            }
            consumed += 8 + length;
        }
        self.mux.drain(..consumed);
        Ok(events)
    }
    fn close(&mut self) -> Result<()> {
        self.closed = true;
        ensure!(
            self.mux.is_empty() && self.chain.is_empty(),
            "truncated observed mux/chain-sync message"
        );
        Ok(())
    }
}
#[derive(Default)]
struct Connection {
    up: Stream,
    down: Stream,
    pending: Option<Vec<Point>>,
    failed: bool,
}
#[derive(Default)]
struct State {
    connections: BTreeMap<u64, Connection>,
    observations: Vec<Observation>,
    errors: Vec<String>,
}
/// A shared passive tap. Errors invalidate evidence but do not interfere with transport.
#[derive(Clone, Default)]
pub struct Observer(Arc<Mutex<State>>);
impl Observer {
    fn apply(&self, id: u64, operation: impl FnOnce(&mut Connection) -> Result<Vec<Event>>) {
        let mut state = self.0.lock().unwrap();
        if !state.connections.contains_key(&id) && state.connections.len() >= CONNECTION_LIMIT {
            if state.errors.len() < 16 {
                state
                    .errors
                    .push("connection observation limit exceeded".into());
            }
            return;
        }
        let connection = state.connections.entry(id).or_default();
        if connection.failed {
            return;
        }
        let result = (|| -> Result<Vec<Event>> {
            let events = operation(connection)?;
            for event in &events {
                match event {
                    Event::Offered { points } => {
                        ensure!(
                            connection.pending.is_none(),
                            "overlapping intersection requests"
                        );
                        connection.pending = Some(points.clone());
                    }
                    Event::Accepted { point, .. } => {
                        let offered = connection
                            .pending
                            .take()
                            .context("intersection response without request")?;
                        ensure!(
                            offered.contains(point),
                            "node accepted an unoffered chain point"
                        );
                    }
                    Event::NotFound { .. } => {
                        ensure!(
                            connection.pending.take().is_some(),
                            "intersection failure without request"
                        );
                    }
                    Event::RolledBack { .. } => {}
                }
            }
            if connection.up.closed && connection.down.closed {
                ensure!(
                    connection.pending.is_none(),
                    "connection closed during intersection negotiation"
                );
            }
            Ok(events)
        })();
        match result {
            Ok(events) => {
                if state
                    .observations
                    .len()
                    .checked_add(events.len())
                    .is_some_and(|n| n <= EVENT_LIMIT)
                {
                    state
                        .observations
                        .extend(events.into_iter().map(|event| Observation {
                            connection: id,
                            event,
                        }));
                } else {
                    state.connections.get_mut(&id).unwrap().failed = true;
                    if state.errors.len() < 16 {
                        state
                            .errors
                            .push("chain-sync observation event limit exceeded".into());
                    }
                }
            }
            Err(error) => {
                let connection = state.connections.get_mut(&id).unwrap();
                connection.failed = true;
                connection.up.mux.clear();
                connection.up.chain.clear();
                connection.down.mux.clear();
                connection.down.chain.clear();
                if state.errors.len() < 16 {
                    state.errors.push(format!("connection{id}: {error:#}"));
                }
            }
        }
    }
    pub fn bytes(&self, id: u64, upstream: bool, bytes: &[u8]) {
        self.apply(id, |connection| {
            if upstream {
                connection.up.push(bytes, true)
            } else {
                connection.down.push(bytes, false)
            }
        });
    }
    pub fn close(&self, id: u64, upstream: bool) {
        self.apply(id, |connection| {
            if upstream {
                connection.up.close()?;
            } else {
                connection.down.close()?;
            }
            Ok(Vec::new())
        });
    }
    pub fn snapshot(&self) -> Snapshot {
        let state = self.0.lock().unwrap();
        Snapshot {
            observations: state.observations.clone(),
            errors: state.errors.clone(),
            connections: state.connections.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash_point(slot: u64, byte: u8) -> Vec<u8> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(2)
            .unwrap()
            .u64(slot)
            .unwrap()
            .bytes(&[byte; 32])
            .unwrap();
        encoder.into_writer()
    }
    fn frame(payload: &[u8], upstream: bool, protocol: u16) -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0];
        bytes.extend_from_slice(&(protocol | if upstream { 0 } else { 0x8000 }).to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
    fn offered(point: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x82, 4, 0x81];
        bytes.extend_from_slice(point);
        bytes
    }
    fn accepted(point: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x83, 5];
        bytes.extend_from_slice(point);
        bytes.push(0x82);
        bytes.extend_from_slice(&hash_point(200, 0xbb));
        bytes.push(20);
        bytes
    }
    #[test]
    fn fragmented_mux_and_cbor_preserve_exact_connection_point_and_tip() {
        let observer = Observer::default();
        let point = hash_point(150, 0xaa);
        let request = offered(&point);
        // CBOR splits across mux frames; mux headers and payload split across reads.
        let mut wire = frame(&request[..9], true, 5);
        wire.extend(frame(&[0xff, 0x00], true, 7)); // unrelated opaque protocol
        wire.extend(frame(&request[9..], true, 5));
        for byte in wire {
            observer.bytes(7, true, &[byte]);
        }
        let response = frame(&accepted(&point), false, 5);
        for bytes in response.chunks(3) {
            observer.bytes(7, false, bytes);
        }
        observer.close(7, true);
        observer.close(7, false);
        let snapshot = observer.snapshot();
        assert!(snapshot.errors.is_empty(), "{:?}", snapshot.errors);
        assert_eq!(snapshot.observations.len(), 2);
        assert_eq!(snapshot.connections, 1);
        assert!(
            matches!(&snapshot.observations[1],Observation{connection:7,event:Event::Accepted{point:Point::Block{slot:150,hash},tip:Tip{point:Point::Block{slot:200,..},height:Some(20)}}} if hash==&"aa".repeat(32))
        );
    }
    #[test]
    fn response_must_match_the_same_connection_and_an_actually_offered_full_hash() {
        for (request_connection, response_point) in [
            (2, hash_point(150, 0xaa)),
            (1, hash_point(150, 0xab)),
            (1, hash_point(151, 0xaa)),
        ] {
            let observer = Observer::default();
            observer.bytes(
                request_connection,
                true,
                &frame(&offered(&hash_point(150, 0xaa)), true, 5),
            );
            observer.bytes(1, false, &frame(&accepted(&response_point), false, 5));
            assert_eq!(observer.snapshot().errors.len(), 1);
            assert!(!observer
                .snapshot()
                .observations
                .iter()
                .any(|v| matches!(v.event, Event::Accepted { .. })));
        }
    }
    #[test]
    fn genesis_and_not_found_are_explicit_and_never_invent_a_block_checkpoint() {
        let observer = Observer::default();
        observer.bytes(1, true, &frame(&offered(&[0x80]), true, 5));
        observer.bytes(1, false, &frame(&[0x82, 6, 0x82, 0x80, 0], false, 5));
        observer.bytes(1, true, &frame(&offered(&[0x80]), true, 5));
        let mut response = vec![0x83, 5, 0x80, 0x82];
        response.extend(hash_point(200, 0xbb));
        response.push(20);
        observer.bytes(1, false, &frame(&response, false, 5));
        observer.close(1, true);
        observer.close(1, false);
        assert!(observer.snapshot().errors.is_empty());
        assert!(matches!(
            observer.snapshot().observations[3].event,
            Event::Accepted {
                point: Point::Origin,
                ..
            }
        ));
    }
    #[test]
    fn malformed_roles_hashes_mux_and_truncated_closure_are_failures() {
        let malformed_hash = vec![0x82, 4, 0x81, 0x82, 1, 0x41, 0xaa];
        for (wire, upstream) in [
            (frame(&malformed_hash, true, 5), true),
            (frame(&[0x81, 0], false, 5), false),
            (frame(&[0x81, 0], false, 5), true),
            (vec![0, 0, 0, 0, 0, 5, 0, 0], true),
            (vec![0, 0, 0], true),
            (frame(&[0x82, 4], true, 5), true),
        ] {
            let observer = Observer::default();
            observer.bytes(1, upstream, &wire);
            observer.close(1, upstream);
            assert!(!observer.snapshot().errors.is_empty());
        }
        let observer = Observer::default();
        observer.bytes(1, true, &frame(&offered(&hash_point(1, 2)), true, 5));
        observer.close(1, true);
        observer.close(1, false);
        assert!(observer.snapshot().errors[0].contains("during intersection"));
    }
    #[test]
    fn oversized_observation_fails_once_and_stops_retaining_input() {
        let observer = Observer::default();
        observer.bytes(1, true, &vec![0; STREAM_LIMIT + 1]);
        for _ in 0..10 {
            observer.bytes(1, true, &[1; 64]);
        }
        assert_eq!(observer.snapshot().errors.len(), 1);
        assert!(observer.snapshot().observations.is_empty());
    }
    #[test]
    fn coalesced_next_await_forward_and_rollback_do_not_store_block_payloads() {
        let observer = Observer::default();
        let mut up = frame(&[0x81, 0, 0x81, 0], true, 5);
        up.extend(frame(&[0x81, 7], true, 5));
        observer.bytes(9, true, &up);
        let mut messages = vec![0x81, 1, 0x83, 2, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x82];
        messages.extend(hash_point(200, 0xbb));
        messages.push(20);
        messages.extend([0x83, 3]);
        messages.extend(hash_point(150, 0xaa));
        messages.push(0x82);
        messages.extend(hash_point(200, 0xbb));
        messages.push(20);
        observer.bytes(9, false, &frame(&messages, false, 5));
        observer.close(9, true);
        observer.close(9, false);
        let snapshot = observer.snapshot();
        assert!(snapshot.errors.is_empty(), "{:?}", snapshot.errors);
        assert_eq!(snapshot.observations.len(), 1);
        assert!(matches!(
            snapshot.observations[0].event,
            Event::RolledBack { .. }
        ));
        assert!(!serde_json::to_string(&snapshot)
            .unwrap()
            .contains("deadbeef"));
    }
}
