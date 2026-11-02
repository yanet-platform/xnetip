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
            "t" => {
                let bytes: Vec<u8> = (0..t[1].len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&t[1][i..i + 2], 16).unwrap())
                    .collect();
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
