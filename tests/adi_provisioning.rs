//! Byte-level parity with a captured apple-auth provisioning transcript.

use apw::adi::{Entropy, Platform, Provisioning};
use base64::Engine as _;

fn hex<const N: usize>(value: &str) -> [u8; N] {
    data_encoding::HEXLOWER
        .decode(value.as_bytes())
        .unwrap()
        .try_into()
        .unwrap()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    data_encoding::HEXLOWER.decode(value.as_bytes()).unwrap()
}

fn base64(value: &str) -> Vec<u8> {
    // Apple returns `ptm` without padding; the other fields are padded.
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value.as_bytes()))
        .unwrap()
}

#[test]
fn provisioning_matches_the_reference_transcript() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/adi/provisioning.json")).unwrap();

    for (name, case) in document.as_object().unwrap() {
        let platform = match case["platform"].as_str().unwrap() {
            "mac" => Platform::Mac,
            "windows" => Platform::Windows,
            other => panic!("{name}: unknown platform {other}"),
        };
        let challenge = hex::<347>(case["challenge"].as_str().unwrap());
        let hardware = hex::<20>(case["identity"]["hardware_hash"].as_str().unwrap());
        let entropy = hex::<132>(case["entropy"].as_str().unwrap());
        let mut session = Provisioning::new(
            &challenge,
            &hardware,
            case["seconds"].as_u64().unwrap() as u32,
            platform,
            Entropy {
                selector: entropy[..32].try_into().unwrap(),
                body: entropy[32..116].try_into().unwrap(),
                nonce: entropy[116..].try_into().unwrap(),
            },
        )
        .unwrap();

        let request = base64(case["cpim"].as_str().unwrap());
        assert_eq!(session.request(), request.as_slice(), "{name}: CPIM");

        let ptm = hex_bytes(case["ptm"].as_str().unwrap());
        let trust_key = hex::<16>(case["tk"].as_str().unwrap());
        let profile = session.finish(&ptm, &trust_key).unwrap();

        let expected = &case["profile"];
        assert_eq!(
            profile.machine_id,
            hex::<60>(expected["profile_data"].as_str().unwrap()),
            "{name}: machine ID"
        );
        assert_eq!(
            profile.secondary,
            base64(expected["secondary"].as_str().unwrap()),
            "{name}: secondary"
        );
        assert_eq!(
            profile.encrypted_seed,
            hex::<32>(expected["encrypted_seed"].as_str().unwrap()),
            "{name}: seed"
        );
        assert_eq!(
            profile.extra_data,
            hex::<8>(expected["extra_data"].as_str().unwrap()),
            "{name}: extra data"
        );
        assert_eq!(
            profile.option,
            expected["option"].as_u64().map(|value| value as u32),
            "{name}: option"
        );
        assert_eq!(
            profile.machine_id_header(),
            case["machine_id"].as_str().unwrap(),
            "{name}: machine ID header"
        );
        for counter in ["0", "1", "12345"] {
            assert_eq!(
                profile.otp_header(counter.parse().unwrap()),
                case["otp"][counter].as_str().unwrap(),
                "{name}: counter {counter}"
            );
        }
    }
}
