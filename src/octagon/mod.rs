//! Octagon trust: peer identity, trust changes, and the escrow join.

pub mod escrow;
pub mod keys;
pub mod proto;

use chrono::Utc;
use rand::RngCore;

use crate::cloudkit::Gateway;
use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

use self::escrow::{Bottle, Escrow, Recovered};
use self::keys::{PeerKeys, PEER_DYNAMIC_INFO, PEER_PERMANENT_INFO, PEER_STABLE_INFO, VOUCHER};

pub struct Peer {
    pub id: String,
    pub keys: PeerKeys,
    pub permanent: Vec<u8>,
    pub permanent_signature: Vec<u8>,
    pub machine_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub id: String,
    pub stable_clock: u64,
    pub dynamic_clock: u64,
    pub included: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Trust {
    pub restore_point: Vec<u8>,
    pub peers: Vec<PeerInfo>,
}

impl Peer {
    pub fn generate(machine_id: &str, model: &str) -> Result<Self> {
        let keys = PeerKeys::generate();
        let permanent = proto::permanent_info(
            1,
            &keys.signing_spki()?,
            &keys.encryption_spki()?,
            machine_id,
            model,
            Utc::now().timestamp() as u64,
        );
        let permanent_signature = keys.sign(PEER_PERMANENT_INFO, &permanent)?;
        let id = keys::peer_id(&permanent, &permanent_signature);
        Ok(Self {
            id,
            keys,
            permanent,
            permanent_signature,
            machine_id: machine_id.to_string(),
        })
    }

    pub fn permanent_signed(&self) -> Writer {
        proto::signed_info(&self.permanent, &self.permanent_signature)
    }
}

/// Read the trust changes and the restore point.
pub async fn fetch_changes(gateway: &Gateway) -> Result<Trust> {
    let request = Writer::new();
    let response = gateway.invoke("fetchChanges", request.as_slice()).await?;
    parse_changes(&response)
}

/// Fetch the escrow bottle, join with a sponsor voucher, and return the new trust state.
pub async fn join(
    gateway: &Gateway,
    escrow: &Escrow,
    peer: &Peer,
    passcode: &[u8],
    adsid: &str,
) -> Result<(Trust, Bottle, Recovered)> {
    let mut bottles_request = Writer::new();
    bottles_request.uint64(1, 1).bytes(2, &[]);
    let bottles = escrow::parse_bottles(
        &gateway
            .invoke("fetchViableBottles", bottles_request.as_slice())
            .await?,
    )?;
    let bottle = bottles
        .into_iter()
        .next()
        .ok_or_else(|| Error::Message("the account has no escrow bottle".into()))?;

    let entropy = escrow.entropy(&bottle.label, passcode, adsid).await?;
    let sponsor = escrow::recover_identity(&bottle, &entropy, adsid)?;

    let mut trust = fetch_changes(gateway).await?;
    let sponsor_info = trust
        .peers
        .iter()
        .find(|info| info.id == sponsor.peer_id)
        .cloned()
        .unwrap_or_default();

    let stable_clock = trust
        .peers
        .iter()
        .map(|info| info.stable_clock)
        .max()
        .unwrap_or(0)
        + 1;
    let dynamic_clock = sponsor_info.dynamic_clock + 1;
    let mut included = sponsor_info.included.clone();
    if !included.iter().any(|id| id == &peer.id) {
        included.push(peer.id.clone());
    }
    included.sort();
    included.dedup();

    let stable = proto::stable_info(stable_clock, "13.4.1", "apw", &peer.machine_id);
    let stable_signature = peer.keys.sign(PEER_STABLE_INFO, &stable)?;
    let dynamic = proto::dynamic_info(dynamic_clock, &included);
    let dynamic_signature = peer.keys.sign(PEER_DYNAMIC_INFO, &dynamic)?;

    let voucher = proto::voucher(1, &peer.id, &sponsor.peer_id);
    let voucher_signature = sponsor.keys.sign(VOUCHER, &voucher)?;

    let peer_message = proto::peer(
        &peer.id,
        &peer.permanent_signed(),
        &proto::signed_info(&stable, &stable_signature),
        &proto::signed_info(&dynamic, &dynamic_signature),
        &proto::signed_info(&voucher, &voucher_signature),
    );

    let mut request = Writer::new();
    request.bytes(1, &trust.restore_point);
    request.bytes(2, &peer_message);
    let response = gateway
        .invoke("joinWithVoucher", request.as_slice())
        .await?;

    if let Ok(updated) = parse_changes(&response) {
        if !updated.restore_point.is_empty() {
            trust = updated;
        }
    }
    Ok((trust, bottle, sponsor))
}

/// Fetch the TLK shares visible to one peer. Call it for the new peer and the
/// recovered sponsor, then union the results.
pub async fn tlk_shares(gateway: &Gateway, peer_id: &str) -> Result<Vec<u8>> {
    let mut request = Writer::new();
    request.string(1, peer_id);
    gateway
        .invoke("fetchRecoverableTlkshares", request.as_slice())
        .await
}

fn parse_changes(data: &[u8]) -> Result<Trust> {
    let mut reader = Reader::new(data);
    let mut trust = Trust::default();
    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let mut changes = field.message()?;
        while let Some(item) = changes.next()? {
            match item.number {
                1 => trust.restore_point = item.bytes()?.to_vec(),
                2 => {
                    let mut change = item.message()?;
                    while let Some(entry) = change.next()? {
                        if entry.number == 3 {
                            trust.peers.push(parse_peer(entry.bytes()?)?);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(trust)
}

fn parse_peer(data: &[u8]) -> Result<PeerInfo> {
    let mut reader = Reader::new(data);
    let mut info = PeerInfo::default();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => info.id = field.string()?.to_string(),
            3 => {
                let (data, _signature) = parse_signed(field.bytes()?)?;
                info.stable_clock = first_varint(&data, 1)?.unwrap_or(0);
            }
            4 => {
                let (data, _signature) = parse_signed(field.bytes()?)?;
                let mut reader = Reader::new(&data);
                while let Some(item) = reader.next()? {
                    match item.number {
                        1 => info.dynamic_clock = item.varint()?,
                        2 => info.included.push(item.string()?.to_string()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(info)
}

fn parse_signed(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut reader = Reader::new(data);
    let mut info = Vec::new();
    let mut signature = Vec::new();
    while let Some(field) = reader.next()? {
        match field.number {
            1 => info = field.bytes()?.to_vec(),
            2 => signature = field.bytes()?.to_vec(),
            _ => {}
        }
    }
    Ok((info, signature))
}

fn first_varint(data: &[u8], number: u32) -> Result<Option<u64>> {
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        if field.number == number {
            return Ok(Some(field.varint()?));
        }
    }
    Ok(None)
}

pub fn machine_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = data_encoding::HEXUPPER.encode(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_generates_a_stable_id() {
        let peer = Peer::generate("machine", "MacBookPro18,3").unwrap();
        assert!(peer.id.starts_with("SHA256:"));
        assert_eq!(
            peer.id,
            keys::peer_id(&peer.permanent, &peer.permanent_signature)
        );
    }

    #[test]
    fn parses_a_trust_change() {
        let peer = Peer::generate("machine", "MacBookPro18,3").unwrap();
        let stable = proto::stable_info(4, "13.4.1", "apw", "machine");
        let stable_signature = peer.keys.sign(PEER_STABLE_INFO, &stable).unwrap();
        let dynamic = proto::dynamic_info(7, &["a".into(), "b".into()]);
        let dynamic_signature = peer.keys.sign(PEER_DYNAMIC_INFO, &dynamic).unwrap();

        let mut message = Writer::new();
        message.string(1, &peer.id);
        message.message(3, &proto::signed_info(&stable, &stable_signature));
        message.message(4, &proto::signed_info(&dynamic, &dynamic_signature));

        let mut change = Writer::new();
        change.message(3, &message);
        let mut changes = Writer::new();
        changes.bytes(1, b"restore");
        changes.message(2, &change);
        let mut response = Writer::new();
        response.message(1, &changes);

        let trust = parse_changes(response.as_slice()).unwrap();
        assert_eq!(trust.restore_point, b"restore");
        assert_eq!(trust.peers.len(), 1);
        assert_eq!(trust.peers[0].stable_clock, 4);
        assert_eq!(trust.peers[0].dynamic_clock, 7);
        assert_eq!(trust.peers[0].included, vec!["a", "b"]);
    }
}
