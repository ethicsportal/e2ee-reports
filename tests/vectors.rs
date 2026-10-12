//! Known-answer tests. `test-vectors/v1.json` is the reference other
//! implementations should reproduce byte for byte.
//!
//! Regenerate after an intentional protocol change with:
//! `cargo test --test vectors -- --ignored --nocapture print_vectors`

use e2ee_reports::{open, seal_with_ephemeral, ChannelSecret, Envelope, ThreadMessage};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Vector {
    description: String,
    channel_secret: String,
    channel_public: String,
    ephemeral_secret: String,
    report: String,
    envelope: String,
    thread_id: String,
    follow_ups: Vec<FollowUp>,
}

#[derive(Serialize, Deserialize)]
struct FollowUp {
    from: String,
    message: String,
    ciphertext: String,
}

struct Case {
    description: &'static str,
    channel_secret: [u8; 32],
    ephemeral_secret: [u8; 32],
    report: &'static str,
    follow_ups: &'static [(&'static str, &'static str)],
}

const CASES: &[Case] = &[
    Case {
        description: "short report, one reply each way",
        channel_secret: counting(0x00),
        ephemeral_secret: counting(0x20),
        report: "Invoices for the bridge repair were paid twice.",
        follow_ups: &[
            ("recipient", "Which month were the second payments made?"),
            ("reporter", "March and April."),
        ],
    },
    Case {
        description: "non-ASCII report, two replies from the recipient in a row",
        channel_secret: counting(0x40),
        ephemeral_secret: counting(0x60),
        report: "Керівник відділу вимагає готівку за погодження контрактів.",
        follow_ups: &[
            ("recipient", "Дякуємо. Чи є свідки?"),
            ("recipient", "Ми почали перевірку."),
            ("reporter", "Так, двоє колег."),
        ],
    },
    Case {
        description: "empty report, no follow-up",
        channel_secret: counting(0x80),
        ephemeral_secret: counting(0xa0),
        report: "",
        follow_ups: &[],
    },
];

const fn counting(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = start.wrapping_add(i as u8);
        i += 1;
    }
    out
}

fn compute(case: &Case) -> Vector {
    let channel = ChannelSecret::from_bytes(case.channel_secret);
    let sealed = seal_with_ephemeral(
        case.ephemeral_secret,
        &channel.public_key(),
        case.report.as_bytes(),
    )
    .unwrap();
    let mut reporter = sealed.thread;
    let mut recipient = open(&channel, &sealed.envelope).unwrap().thread;

    let follow_ups = case
        .follow_ups
        .iter()
        .map(|(from, message)| {
            let (sender, receiver) = match *from {
                "reporter" => (&mut reporter, &mut recipient),
                _ => (&mut recipient, &mut reporter),
            };
            let encrypted = sender.encrypt(message.as_bytes()).unwrap();
            assert_eq!(receiver.decrypt(&encrypted).unwrap(), message.as_bytes());
            FollowUp {
                from: from.to_string(),
                message: message.to_string(),
                ciphertext: hex::encode(encrypted.to_bytes()),
            }
        })
        .collect();

    Vector {
        description: case.description.to_string(),
        channel_secret: hex::encode(case.channel_secret),
        channel_public: hex::encode(channel.public_key().as_bytes()),
        ephemeral_secret: hex::encode(case.ephemeral_secret),
        report: case.report.to_string(),
        envelope: hex::encode(sealed.envelope.to_bytes()),
        thread_id: hex::encode(reporter.id()),
        follow_ups,
    }
}

fn published() -> Vec<Vector> {
    serde_json::from_str(include_str!("../test-vectors/v1.json")).unwrap()
}

#[test]
fn implementation_reproduces_published_vectors() {
    let published = published();
    assert_eq!(published.len(), CASES.len());
    for (case, expected) in CASES.iter().zip(&published) {
        let actual = compute(case);
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(expected).unwrap(),
            "{}",
            case.description
        );
    }
}

#[test]
fn published_vectors_decrypt_from_their_bytes_alone() {
    for vector in published() {
        let secret: [u8; 32] = hex::decode(&vector.channel_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let channel = ChannelSecret::from_bytes(secret);
        let envelope = Envelope::from_bytes(&hex::decode(&vector.envelope).unwrap()).unwrap();
        let opened = open(&channel, &envelope).unwrap();
        assert_eq!(opened.report, vector.report.as_bytes());

        let mut recipient = opened.thread;
        for follow_up in &vector.follow_ups {
            let message =
                ThreadMessage::from_bytes(&hex::decode(&follow_up.ciphertext).unwrap()).unwrap();
            if follow_up.from == "reporter" {
                assert_eq!(
                    recipient.decrypt(&message).unwrap(),
                    follow_up.message.as_bytes()
                );
            } else {
                assert!(recipient.decrypt(&message).is_err());
            }
        }
    }
}

#[test]
#[ignore]
fn print_vectors() {
    let vectors: Vec<Vector> = CASES.iter().map(compute).collect();
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
