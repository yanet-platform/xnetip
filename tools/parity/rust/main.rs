use netip::*;
use std::{
    io::{self, BufRead},
    net::{Ipv4Addr, Ipv6Addr},
};
fn n4(a: &str, m: &str) -> Ipv4Network {
    Ipv4Network::from_bits(
        u32::from_str_radix(a, 16).unwrap(),
        u32::from_str_radix(m, 16).unwrap(),
    )
}
fn n6(a: &str, m: &str) -> Ipv6Network {
    Ipv6Network::from_bits(
        u128::from_str_radix(a, 16).unwrap(),
        u128::from_str_radix(m, 16).unwrap(),
    )
}
fn s4(n: Ipv4Network) -> String {
    let (a, m) = n.to_bits();
    format!("{a:08x}/{m:08x}")
}
fn s6(n: Ipv6Network) -> String {
    let (a, m) = n.to_bits();
    format!("{a:032x}/{m:032x}")
}
fn o4(n: Option<Ipv4Network>) -> String {
    n.map(s4).unwrap_or("-".into())
}
fn o6(n: Option<Ipv6Network>) -> String {
    n.map(s6).unwrap_or("-".into())
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let t: Vec<_> = line.split_whitespace().collect();
        if t.is_empty() {
            continue;
        }
        match t[0] {
            "ta" | "tn" => {
                println!(
                    "{}",
                    ascii_results(&decode_bytes(t[1]), t[0] == "tn").join(";")
                );
            }
            "s4" => {
                let parent = n4(t[1], t[2]);
                let mask = Ipv4Addr::from_bits(u32::from_str_radix(t[3], 16).unwrap());
                let children = parent
                    .subnets(mask)
                    .map(|it| it.take(8).map(s4).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let prefix = t[4].parse::<u8>().unwrap();
                let cidrs = parent
                    .subnets_with_prefix(prefix)
                    .map(|it| it.take(8).map(|n| s4(*n)).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let reverse_children = parent
                    .subnets(mask)
                    .map(|it| it.rev().take(8).map(s4).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let reverse_cidrs = parent
                    .subnets_with_prefix(prefix)
                    .map(|it| {
                        it.rev()
                            .take(8)
                            .map(|n| s4(*n))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                println!("{children}|{cidrs}|{reverse_children}|{reverse_cidrs}");
            }
            "s6" => {
                let parent = n6(t[1], t[2]);
                let mask = Ipv6Addr::from_bits(u128::from_str_radix(t[3], 16).unwrap());
                let children = parent
                    .subnets(mask)
                    .map(|it| it.take(8).map(s6).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let prefix = t[4].parse::<u8>().unwrap();
                let cidrs = parent
                    .subnets_with_prefix(prefix)
                    .map(|it| it.take(8).map(|n| s6(*n)).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let reverse_children = parent
                    .subnets(mask)
                    .map(|it| it.rev().take(8).map(s6).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let reverse_cidrs = parent
                    .subnets_with_prefix(prefix)
                    .map(|it| {
                        it.rev()
                            .take(8)
                            .map(|n| s6(*n))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                println!("{children}|{cidrs}|{reverse_children}|{reverse_cidrs}");
            }
            "i4" => {
                let mut cursor = n4(t[1], t[2]).addrs();
                let mut results = vec![cursor_size(&cursor)];
                for step in t[3..].chunks(2) {
                    let skip = u64::from_str_radix(step[1], 16).unwrap() as usize;
                    let address = if step[0] == "f" {
                        cursor.nth(skip)
                    } else {
                        cursor.nth_back(skip)
                    };
                    results.push(format!(
                        "{}:{}",
                        address
                            .map(|a| format!("{:08x}", a.to_bits()))
                            .unwrap_or("-".into()),
                        cursor_size(&cursor)
                    ));
                }
                println!("{}", results.join("|"));
            }
            "i6" => {
                let mut cursor = n6(t[1], t[2]).addrs();
                let mut results = vec![cursor_size(&cursor)];
                for step in t[3..].chunks(2) {
                    let skip = u64::from_str_radix(step[1], 16).unwrap() as usize;
                    let address = if step[0] == "f" {
                        cursor.nth(skip)
                    } else {
                        cursor.nth_back(skip)
                    };
                    results.push(format!(
                        "{}:{}",
                        address
                            .map(|a| format!("{:032x}", a.to_bits()))
                            .unwrap_or("-".into()),
                        cursor_size(&cursor)
                    ));
                }
                println!("{}", results.join("|"));
            }
            "j4" => {
                let mut projected: Vec<_> = t[1..]
                    .chunks(2)
                    .enumerate()
                    .map(|(payload, n)| Projected4 {
                        network: n4(n[0], n[1]),
                        payload,
                    })
                    .collect();
                projected.sort_by_key(|p| p.network);
                let (candidate, start, end) = ipv4_binary_split(&mut projected)
                    .map(|(n, r)| (s4(n), r.start, r.end))
                    .unwrap_or(("-".into(), 0, 0));
                let mut results = vec![candidate, format!("{start}:{end}")];
                results.extend(
                    projected
                        .iter()
                        .map(|p| format!("{}:{}", p.payload, s4(p.network))),
                );
                println!("{}", results.join("|"));
            }
            "j6" => {
                let mut projected: Vec<_> = t[1..]
                    .chunks(2)
                    .enumerate()
                    .map(|(payload, n)| Projected6 {
                        network: n6(n[0], n[1]),
                        payload,
                    })
                    .collect();
                projected.sort_by_key(|p| p.network);
                let (candidate, start, end) = ipv6_binary_split(&mut projected)
                    .map(|(n, r)| (s6(n), r.start, r.end))
                    .unwrap_or(("-".into(), 0, 0));
                let mut results = vec![candidate, format!("{start}:{end}")];
                results.extend(
                    projected
                        .iter()
                        .map(|p| format!("{}:{}", p.payload, s6(p.network))),
                );
                println!("{}", results.join("|"));
            }
            "m" => {
                let value = u64::from_str_radix(t[1], 16).unwrap();
                match MacAddr::from_u64(value) {
                    None => println!("ERR"),
                    Some(mac) => println!(
                        "{:012x}|{}{}{}{}{}{}|{}|{:X}|{}|{:X}|{}|{:X}|{:016x}|{:032x}",
                        mac.as_u64(),
                        mac.is_zero() as u8,
                        mac.is_broadcast() as u8,
                        mac.is_multicast() as u8,
                        mac.is_unicast() as u8,
                        mac.is_locally_administered() as u8,
                        mac.is_universally_administered() as u8,
                        mac,
                        mac,
                        netip::fmt::MacHyphens(mac),
                        netip::fmt::MacHyphens(mac),
                        netip::fmt::MacDots(mac),
                        netip::fmt::MacDots(mac),
                        mac.to_modified_eui64(),
                        mac.to_ipv6_link_local().to_bits()
                    ),
                }
            }
            "mt" => match MacAddr::parse_ascii(&decode_bytes(t[1])) {
                Ok(mac) => println!("{mac}"),
                Err(_) => println!("ERR"),
            },
            "e" => {
                println!(
                    "{}",
                    optional_mac(MacAddr::from_modified_eui64(
                        u64::from_str_radix(t[1], 16).unwrap()
                    ))
                );
            }
            "v4" => {
                println!(
                    "{}",
                    optional_mac(MacAddr::from_ipv4_multicast(Ipv4Addr::from_bits(
                        u32::from_str_radix(t[1], 16).unwrap()
                    )))
                );
            }
            "v6" => {
                println!(
                    "{}",
                    optional_mac(MacAddr::from_ipv6_multicast(Ipv6Addr::from_bits(
                        u128::from_str_radix(t[1], 16).unwrap()
                    )))
                );
            }
            "t" => {
                let bytes = decode_bytes(t[1]);
                match IpNetwork::parse_ascii(&bytes) {
                    Ok(n) => println!("OK|{n}"),
                    Err(_) => println!("ERR"),
                }
            }
            "p4" => {
                let a = n4(t[1], t[2]);
                let b = n4(t[3], t[4]);
                let fields = vec![
                    s4(a),
                    s4(b),
                    format!(
                        "{}{}{}{}{}",
                        a.contains(&b) as u8,
                        a.intersects(&b) as u8,
                        a.is_disjoint(&b) as u8,
                        a.is_adjacent(&b) as u8,
                        a.is_adjacent_by_lowest_mask_bit(&b) as u8
                    ),
                    o4(a.intersection(&b)),
                    o4(a.merge(&b)),
                    o4(a.merge_by_lowest_mask_bit(&b)),
                    s4(a.supernet_for(&[b])),
                    s4(a.to_contiguous()),
                    a.host_bits().to_string(),
                    format!("{:?}", a.prefix()),
                    a.difference(&b).map(s4).collect::<Vec<_>>().join(","),
                    a.addrs()
                        .take(8)
                        .map(|v| format!("{:08x}", v.to_bits()))
                        .collect::<Vec<_>>()
                        .join(","),
                    a.addrs()
                        .rev()
                        .take(8)
                        .map(|v| format!("{:08x}", v.to_bits()))
                        .collect::<Vec<_>>()
                        .join(","),
                    s6(a.to_ipv6_mapped()),
                    a.to_string(),
                    a.cmp(&b).is_lt().to_string(),
                    format!("{:08x}", a.hostmask().to_bits()),
                    o4(a.supernet()),
                    a.difference(&b).rev().map(s4).collect::<Vec<_>>().join(","),
                ];
                println!("{}", fields.join("|"));
            }
            "p6" => {
                let a = n6(t[1], t[2]);
                let b = n6(t[3], t[4]);
                let fields = vec![
                    s6(a),
                    s6(b),
                    format!(
                        "{}{}{}{}{}",
                        a.contains(&b) as u8,
                        a.intersects(&b) as u8,
                        a.is_disjoint(&b) as u8,
                        a.is_adjacent(&b) as u8,
                        a.is_adjacent_by_lowest_mask_bit(&b) as u8
                    ),
                    o6(a.intersection(&b)),
                    o6(a.merge(&b)),
                    o6(a.merge_by_lowest_mask_bit(&b)),
                    s6(a.supernet_for(&[b])),
                    s6(a.to_contiguous()),
                    a.host_bits().to_string(),
                    format!("{:?}", a.prefix()),
                    a.difference(&b).map(s6).collect::<Vec<_>>().join(","),
                    a.addrs()
                        .take(8)
                        .map(|v| format!("{:032x}", v.to_bits()))
                        .collect::<Vec<_>>()
                        .join(","),
                    a.addrs()
                        .rev()
                        .take(8)
                        .map(|v| format!("{:032x}", v.to_bits()))
                        .collect::<Vec<_>>()
                        .join(","),
                    format!(
                        "{}:{}:{}",
                        a.is_bicontiguous(),
                        a.is_ipv4_mapped_ipv6(),
                        o4(a.to_ipv4_mapped())
                    ),
                    a.to_string(),
                    a.cmp(&b).is_lt().to_string(),
                    format!("{:032x}", a.hostmask().to_bits()),
                    o6(a.supernet()),
                    a.difference(&b).rev().map(s6).collect::<Vec<_>>().join(","),
                ];
                println!("{}", fields.join("|"));
            }
            "a4" => {
                let mut ns: Vec<_> = t[1..].chunks(2).map(|x| n4(x[0], x[1])).collect();
                let a = ipv4_aggregate(&mut ns);
                println!("{}", a.iter().map(|&x| s4(x)).collect::<Vec<_>>().join(","));
            }
            "a6" => {
                let mut ns: Vec<_> = t[1..].chunks(2).map(|x| n6(x[0], x[1])).collect();
                let a = ipv6_aggregate(&mut ns);
                println!("{}", a.iter().map(|&x| s6(x)).collect::<Vec<_>>().join(","));
            }
            "b6" => {
                let mut ns: Vec<_> = t[1..]
                    .chunks(2)
                    .map(|x| BiContiguous::try_from(n6(x[0], x[1])).unwrap())
                    .collect();
                let a = ipv6_aggregate_bicontiguous(&mut ns);
                println!(
                    "{}",
                    a.iter().map(|x| s6(**x)).collect::<Vec<_>>().join(",")
                );
            }
            "c4" => {
                let mut ns: Vec<_> = t[1..]
                    .chunks(2)
                    .map(|x| Contiguous::try_from(n4(x[0], x[1])).unwrap())
                    .collect();
                let a = ipv4_aggregate_contiguous(&mut ns);
                println!(
                    "{}",
                    a.iter().map(|x| s4(**x)).collect::<Vec<_>>().join(",")
                );
            }
            "c6" => {
                let mut ns: Vec<_> = t[1..]
                    .chunks(2)
                    .map(|x| Contiguous::try_from(n6(x[0], x[1])).unwrap())
                    .collect();
                let a = ipv6_aggregate_contiguous(&mut ns);
                println!(
                    "{}",
                    a.iter().map(|x| s6(**x)).collect::<Vec<_>>().join(",")
                );
            }
            "r4" => {
                let a = Ipv4Addr::from_bits(u32::from_str_radix(t[1], 16).unwrap());
                let b = Ipv4Addr::from_bits(u32::from_str_radix(t[2], 16).unwrap());
                println!(
                    "{}",
                    ipv4_range_to_networks(a, b)
                        .map(|x| s4(*x))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            "r6" => {
                let a = Ipv6Addr::from_bits(u128::from_str_radix(t[1], 16).unwrap());
                let b = Ipv6Addr::from_bits(u128::from_str_radix(t[2], 16).unwrap());
                println!(
                    "{}",
                    ipv6_range_to_networks(a, b)
                        .map(|x| s6(*x))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            _ => panic!("unknown op"),
        }
    }
}

fn decode_bytes(input: &str) -> Vec<u8> {
    if input == "-" {
        return Vec::new();
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}
fn cursor_size(cursor: &impl Iterator) -> String {
    let (lower, upper) = cursor.size_hint();
    format!("{}:{}", lower, upper == Some(lower))
}
struct Projected4 {
    network: Ipv4Network,
    payload: usize,
}
struct Projected6 {
    network: Ipv6Network,
    payload: usize,
}
impl AsRef<Ipv4Network> for Projected4 {
    fn as_ref(&self) -> &Ipv4Network {
        &self.network
    }
}
impl AsRef<Ipv6Network> for Projected6 {
    fn as_ref(&self) -> &Ipv6Network {
        &self.network
    }
}
fn optional_mac(mac: Option<MacAddr>) -> String {
    mac.map(|m| format!("{:012x}", m.as_u64()))
        .unwrap_or("-".into())
}
fn ascii_results(input: &[u8], token: bool) -> Vec<String> {
    fn whole<T: std::fmt::Display, E>(r: Result<T, E>) -> String {
        r.map(|n| format!("OK|{n}")).unwrap_or("ERR".into())
    }
    fn next<T: std::fmt::Display, E>(r: Result<(T, &[u8]), E>) -> String {
        r.map(|(n, rest)| {
            format!(
                "OK|{n}|{}",
                rest.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        })
        .unwrap_or("ERR".into())
    }
    if token {
        vec![
            next(Ipv4Network::parse_next_ascii(input)),
            next(Ipv6Network::parse_next_ascii(input)),
            next(IpNetwork::parse_next_ascii(input)),
        ]
    } else {
        vec![
            whole(Ipv4Network::parse_ascii(input)),
            whole(Ipv6Network::parse_ascii(input)),
            whole(IpNetwork::parse_ascii(input)),
        ]
    }
}
