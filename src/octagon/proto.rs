//! Octagon protobuf messages.

use crate::wire::Writer;

pub const FROZEN_POLICY_VERSION: u64 = 5;
pub const FROZEN_POLICY_HASH: &str = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=";
pub const FLEXIBLE_POLICY_VERSION: u64 = 20;
pub const FLEXIBLE_POLICY_HASH: &str = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=";

pub fn permanent_info(
    epoch: u64,
    signing_spki: &[u8],
    encryption_spki: &[u8],
    machine_id: &str,
    model_id: &str,
    creation_time: u64,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.uint64(1, epoch);
    writer.bytes(2, signing_spki);
    writer.bytes(3, encryption_spki);
    writer.string(4, machine_id);
    writer.string(5, model_id);
    writer.uint64(6, creation_time);
    writer.finish()
}

pub fn stable_info(clock: u64, os_version: &str, device_name: &str, serial: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.uint64(1, clock);
    writer.uint64(2, FROZEN_POLICY_VERSION);
    writer.string(3, FROZEN_POLICY_HASH);
    writer.string(5, os_version);
    writer.string(6, device_name);
    writer.string(9, serial);
    writer.uint64(10, FLEXIBLE_POLICY_VERSION);
    writer.string(11, FLEXIBLE_POLICY_HASH);
    writer.uint64(12, 1);
    writer.boolean(19, true);
    writer.finish()
}

pub fn dynamic_info(clock: u64, included: &[String]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.uint64(1, clock);
    for peer in included {
        writer.string(2, peer);
    }
    writer.finish()
}

pub fn voucher(reason: u64, beneficiary: &str, sponsor: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.uint64(1, reason);
    writer.string(2, beneficiary);
    writer.string(3, sponsor);
    writer.finish()
}

pub fn signed_info(data: &[u8], signature: &[u8]) -> Writer {
    let mut writer = Writer::new();
    writer.bytes(1, data);
    writer.bytes(2, signature);
    writer
}

pub fn peer(
    peer_id: &str,
    permanent: &Writer,
    stable: &Writer,
    dynamic: &Writer,
    voucher: &Writer,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.string(1, peer_id);
    writer.message(2, permanent);
    writer.message(3, stable);
    writer.message(4, dynamic);
    writer.message(5, voucher);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    #[test]
    fn permanent_info_fields() {
        let data = permanent_info(1, b"sign", b"enc", "machine", "MacBookPro18,3", 100);
        let mut reader = Reader::new(&data);
        assert_eq!(reader.next().unwrap().unwrap().varint().unwrap(), 1);
        assert_eq!(reader.next().unwrap().unwrap().bytes().unwrap(), b"sign");
        assert_eq!(reader.next().unwrap().unwrap().bytes().unwrap(), b"enc");
        assert_eq!(reader.next().unwrap().unwrap().string().unwrap(), "machine");
    }

    #[test]
    fn dynamic_info_lists_peers() {
        let data = dynamic_info(2, &["a".into(), "b".into()]);
        let mut reader = Reader::new(&data);
        assert_eq!(reader.next().unwrap().unwrap().varint().unwrap(), 2);
        assert_eq!(reader.next().unwrap().unwrap().string().unwrap(), "a");
        assert_eq!(reader.next().unwrap().unwrap().string().unwrap(), "b");
    }
}
