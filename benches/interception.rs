#![allow(dead_code)]
#![allow(unused_imports)]

#[path = "../src/admin.rs"]
mod admin;
#[path = "../src/backend.rs"]
mod backend;
#[path = "../src/config.rs"]
mod config;
#[allow(unused_imports)]
#[path = "../src/dns.rs"]
mod dns;
#[path = "../src/interfaces.rs"]
mod interfaces;
#[path = "../src/mdns.rs"]
mod mdns;
#[path = "../src/packet.rs"]
mod packet;
#[path = "../src/rules.rs"]
mod rules;

use std::{
    hint::black_box,
    net::Ipv4Addr,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

const DEFAULT_ITERATIONS: usize = 200_000;

fn main() {
    let iterations = std::env::var("DNS_SHUNT_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ITERATIONS);
    println!("interception microbench ({iterations} iterations per case)");

    bench_pass_through(iterations);
    bench_mdns_pass_through(iterations);
    bench_unsupported_query_parse(iterations);
    bench_supported_query_classification(iterations);
    bench_rule_lookup(iterations);
    bench_wildcard_and_mdns_lookup(iterations);
    bench_snapshot_clone();
    bench_receive_lock(iterations);
}

fn bench_pass_through(iterations: usize) {
    let dns_payload = dns_query("unmatched.example", 1, 1, true);
    let small_packet = packet::build_ipv4_udp(
        packet::FlowTuple {
            source: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 53_000,
            destination: std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            destination_port: 53,
        },
        &dns_payload,
    )
    .unwrap();
    let rules = config::CompiledRules::new(Vec::new());
    benchmark_pass_through_packet(
        "typical-sized DNS packet",
        &small_packet,
        &rules,
        iterations,
    );

    let padded_payload = dns_query_with_edns_padding("unmatched.example", 1, 1, 1_150);
    assert!(dns::parse_query(&padded_payload).is_ok());
    let large_packet = packet::build_ipv4_udp(
        packet::FlowTuple {
            source: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 53_000,
            destination: std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            destination_port: 53,
        },
        &padded_payload,
    )
    .unwrap();
    benchmark_pass_through_packet("EDNS-padded DNS packet", &large_packet, &rules, iterations);
}

fn benchmark_pass_through_packet(
    label: &str,
    wire_packet: &[u8],
    rules: &config::CompiledRules,
    iterations: usize,
) {
    println!("\nUnmatched A/IN pass-through ({label}):");
    println!("  modeled copied bytes/op: {}", wire_packet.len());
    measure("receive-buffer copy only", iterations, || {
        black_box(wire_packet.to_vec());
    });
    measure(
        "capture + full section validation + lookup",
        iterations,
        || {
            let captured = wire_packet.to_vec();
            let (tuple, payload) = packet::parse_ipv4_udp(&captured).unwrap();
            let dns::QueryClassification::Eligible(question) =
                dns::classify_query(payload).unwrap()
            else {
                panic!("benchmark query should be eligible");
            };
            dns::validate_query_sections(payload, &question).unwrap();
            black_box(rules.lookup_for_qtype(&question.name, question.qtype));
            black_box((tuple, question, captured));
        },
    );
    measure(
        "capture + question lookup + move to reinject",
        iterations,
        || {
            let captured = wire_packet.to_vec();
            let (tuple, payload) = packet::parse_ipv4_udp(&captured).unwrap();
            let dns::QueryClassification::Eligible(question) =
                dns::classify_query(payload).unwrap()
            else {
                panic!("benchmark query should be eligible");
            };
            black_box(rules.lookup_for_qtype(&question.name, question.qtype));
            black_box((tuple, question, captured));
        },
    );
}

fn bench_mdns_pass_through(iterations: usize) {
    let payload = mdns_query("unmatched.local", true);
    let wire_packet = packet::build_ipv4_udp(
        packet::FlowTuple {
            source: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 53_535,
            destination: std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            destination_port: 5353,
        },
        &payload,
    )
    .unwrap();
    let rules = config::CompiledRules::new(Vec::new());

    println!("\nmDNS no-rule pass-through:");
    println!(
        "  modeled copied bytes/op: old capture+clone={}, staged borrowed={}",
        wire_packet.len() * 2,
        wire_packet.len()
    );
    measure(
        "full parse + rule lookup + forwarding clone",
        iterations,
        || {
            let captured = wire_packet.to_vec();
            let (_, dns_payload) = packet::parse_ipv4_udp(&captured).unwrap();
            let query = mdns::parse_mdns_query(dns_payload, false).unwrap();
            let candidates = mdns::resolve_mdns_query(&rules, &query);
            let forwarded = captured.clone();
            black_box((query, candidates, forwarded));
        },
    );
    measure(
        "full parse + rule lookup + borrowed forwarding",
        iterations,
        || {
            let captured = wire_packet.to_vec();
            let (_, dns_payload) = packet::parse_ipv4_udp(&captured).unwrap();
            let query = mdns::parse_mdns_query(dns_payload, false).unwrap();
            let candidates = mdns::resolve_mdns_query(&rules, &query);
            black_box((query, candidates, captured));
        },
    );
    measure(
        "questions + no-rule lookup + borrowed forwarding",
        iterations,
        || {
            let captured = wire_packet.to_vec();
            let (_, dns_payload) = packet::parse_ipv4_udp(&captured).unwrap();
            let parsed = mdns::parse_mdns_questions(dns_payload, false).unwrap();
            let matched = parsed.questions.iter().any(|question| {
                question.qclass == 1
                    && !rules
                        .lookup_for_mdns(&question.name, question.qtype)
                        .is_empty()
            });
            black_box((matched, parsed, captured));
        },
    );
}

fn bench_unsupported_query_parse(iterations: usize) {
    let message = dns_query("assets.example", 28, 1, true);

    println!("\nUnsupported AAAA/IN query with EDNS0:");
    measure("full parse_query", iterations, || {
        black_box(dns::parse_query(&message).unwrap());
    });
    measure("early type/class classification", iterations, || {
        black_box(dns::classify_query(&message).unwrap());
    });
}

fn bench_supported_query_classification(iterations: usize) {
    let miss = dns_query("missing.example", 1, 1, true);
    let hit = dns_query("assets.example", 1, 1, true);
    let rules = config::CompiledRules::new(
        config::validate_rules(
            vec![config::RuleInput {
                name: "assets.example".into(),
                record_type: Some(config::RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap(),
    );

    println!("\nEligible A/IN queries (classifier includes full validation):");
    for (label, message) in [("A/IN miss", &miss), ("A/IN rule match", &hit)] {
        measure(
            &format!("full parse + lookup ({label})"),
            iterations,
            || {
                let question = dns::parse_query(message).unwrap();
                black_box(rules.lookup_normalized(&question.name));
            },
        );
        measure(
            &format!("classifier + lookup ({label})"),
            iterations,
            || {
                let dns::QueryClassification::Eligible(question) =
                    dns::classify_query(message).unwrap()
                else {
                    panic!("benchmark query should be eligible");
                };
                black_box(rules.lookup_normalized(&question.name));
            },
        );
    }
}

fn bench_rule_lookup(iterations: usize) {
    println!("\nExact-name miss lookup (normalized DNS name):");
    for count in [10, 100, 1_000] {
        let inputs = (0..count)
            .map(|index| config::RuleInput {
                name: format!("host{index:05}.example.test"),
                record_type: Some(config::RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(60),
            })
            .collect();
        let rules = config::validate_rules(inputs, "dns-shunt.local", 60).unwrap();
        let compiled = config::CompiledRules::new(rules.clone());
        let query_name = "missing.example.test";

        measure(&format!("linear scan ({count} rules)"), iterations, || {
            black_box(config::lookup_rule(&rules, query_name));
        });
        measure(
            &format!("compiled lookup ({count} rules)"),
            iterations,
            || {
                black_box(compiled.lookup_normalized(query_name));
            },
        );
    }
}

fn bench_wildcard_and_mdns_lookup(iterations: usize) {
    println!("\nWildcard, mDNS, and CNAME lookup paths (100 rules):");
    let mut inputs: Vec<config::RuleInput> = (0..100)
        .map(|index| config::RuleInput {
            name: format!("host{index:05}.example.test"),
            record_type: Some(config::RuleType::A),
            address: Some("192.0.2.1".into()),
            target: None,
            ttl: Some(60),
        })
        .collect();
    // Wildcard bases of differing depth so the suffix walk is exercised.
    inputs.push(config::RuleInput {
        name: "example.test".into(),
        record_type: Some(config::RuleType::A),
        address: Some("192.0.2.2".into()),
        target: None,
        ttl: Some(60),
    });
    inputs.push(config::RuleInput {
        name: "example.test".into(),
        record_type: Some(config::RuleType::Aaaa),
        address: Some("2001:db8::2".into()),
        target: None,
        ttl: Some(60),
    });
    inputs.push(config::RuleInput {
        name: "wild.test".into(),
        record_type: Some(config::RuleType::Cname),
        address: None,
        target: Some("target.example.net".into()),
        ttl: Some(60),
    });
    let rules = config::validate_rules(inputs, "dns-shunt.local", 60).unwrap();
    let compiled = config::CompiledRules::new(rules);

    for (label, name) in [
        ("wildcard depth 1 (a.example.test)", "a.example.test"),
        (
            "wildcard depth 3 (a.b.c.example.test)",
            "a.b.c.example.test",
        ),
        (
            "wildcard depth 5 (a.b.c.d.e.example.test)",
            "a.b.c.d.e.example.test",
        ),
        ("wildcard miss (a.b.c.unknown.org)", "a.b.c.unknown.org"),
    ] {
        measure(&format!("lookup_for_qtype A {label}"), iterations, || {
            black_box(compiled.lookup_for_qtype(name, 1));
        });
    }
    measure(
        "lookup_for_qtype AAAA exact-miss wildcard",
        iterations,
        || {
            black_box(compiled.lookup_for_qtype("a.b.example.test", 28));
        },
    );
    for qtype in [1u16, 28, 255] {
        measure(
            &format!("lookup_for_mdns qtype={qtype} (a.b.example.test)"),
            iterations,
            || {
                black_box(compiled.lookup_for_mdns("a.b.example.test", qtype));
            },
        );
    }
    measure("lookup_cname (x.wild.test)", iterations, || {
        black_box(compiled.lookup_cname("x.wild.test"));
    });
    measure("lookup_cname miss (a.b.example.test)", iterations, || {
        black_box(compiled.lookup_cname("a.b.example.test"));
    });
}

fn bench_snapshot_clone() {
    const ITERATIONS: usize = 20_000;
    println!("\nRule snapshot retrieval (20,000 iterations per case):");
    for count in [10, 100, 1_000] {
        let inputs = (0..count)
            .map(|index| config::RuleInput {
                name: format!("host{index:05}.example.test"),
                record_type: Some(config::RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(60),
            })
            .collect();
        let rules = config::validate_rules(inputs, "dns-shunt.local", 60).unwrap();
        let copied_snapshot = RwLock::new(rules.clone());
        let shared_snapshot = RwLock::new(Arc::new(config::CompiledRules::new(rules)));

        measure(
            &format!("clone rule vector ({count} rules)"),
            ITERATIONS,
            || {
                let snapshot = copied_snapshot
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                black_box(snapshot);
            },
        );
        measure(
            &format!("clone shared snapshot ({count} rules)"),
            ITERATIONS,
            || {
                let snapshot = Arc::clone(
                    &shared_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                );
                black_box(snapshot);
            },
        );
    }
}

fn bench_receive_lock(iterations: usize) {
    let buffer = vec![0u8; 1_500];
    let locked_buffer = Mutex::new(buffer.clone());

    println!("\nUncontended receive-buffer access:");
    measure("direct buffer access (lower bound)", iterations, || {
        black_box(black_box(&buffer[..]).len());
    });
    measure("Mutex lock + buffer access", iterations, || {
        let buffer = locked_buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        black_box(buffer.len());
    });
}

fn measure(label: &str, iterations: usize, mut operation: impl FnMut()) {
    let warmup = iterations.min(10_000);
    for _ in 0..warmup {
        operation();
    }

    const REPEATS: usize = 5;
    let mut samples = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let nanos_per_operation = samples[REPEATS / 2] as f64 / iterations as f64;
    println!("  {label:<48} {nanos_per_operation:>10.1} ns/op");
}

fn dns_query(name: &str, qtype: u16, qclass: u16, include_edns: bool) -> Vec<u8> {
    let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&qclass.to_be_bytes());
    if include_edns {
        message[10..12].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    }
    message
}

fn dns_query_with_edns_padding(
    name: &str,
    qtype: u16,
    qclass: u16,
    padding_length: usize,
) -> Vec<u8> {
    let mut message = dns_query(name, qtype, qclass, false);
    message[10..12].copy_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
    message.extend_from_slice(&(padding_length as u16).to_be_bytes());
    message.resize(message.len() + padding_length, 0);
    message
}

fn mdns_query(name: &str, include_known_answer: bool) -> Vec<u8> {
    let mut message = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    if include_known_answer {
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        message.extend_from_slice(&[192, 0, 2, 1]);
    }
    message
}
