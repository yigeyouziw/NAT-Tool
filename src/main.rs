use anyhow::{Context, Result};
use igd::{PortMappingProtocol, SearchOptions};
use std::io::{stdout, Write};
use std::net::{IpAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{self, AsyncBufReadExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    loop {
        clear_screen();
        println!("=========================================");
        println!("   RUST NAT TRAVERSAL TOOL   ");
        println!("=========================================");
        println!("1. UPnP Port Mapping (Client)");
        println!("2. UDP Hole Punching Proxy (Client)");
        println!("3. UDP Echo Server (Public Side)");
        println!("4. Exit");
        println!("=========================================");
        print!("Select an option [1-4]: ");
        flush_stdout();

        let choice = read_line_async().await.unwrap_or_default();

        match choice.trim() {
            "1" => {
                if let Err(e) = menu_upnp().await {
                    eprintln!("\nERROR UPnP FAILED: {}", e);
                    wait_for_enter().await;
                }
            }
            "2" => {
                if let Err(e) = menu_proxy().await {
                    eprintln!("\nERROR Proxy FAILED: {}", e);
                    wait_for_enter().await;
                }
            }
            "3" => {
                if let Err(e) = menu_server().await {
                    eprintln!("\nERROR Server FAILED: {}", e);
                    wait_for_enter().await;
                }
            }
            "4" => {
                println!("Bye!");
                break;
            }
            _ => {
                println!("Invalid option.");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn get_public_addr(socket: &UdpSocket, server: &str) -> Result<String> {
    println!("   -> Probing public address via {} ...", server);

    let mut stun_req = vec![0u8; 20];
    stun_req[0] = 0x00;
    stun_req[1] = 0x01; // Message Type: Binding Request
    stun_req[2] = 0x00;
    stun_req[3] = 0x00; // Message Length: 0
    stun_req[4] = 0x21;
    stun_req[5] = 0x12;
    stun_req[6] = 0xA4;
    stun_req[7] = 0x42; // Magic Cookie

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let unique_id = nanos.to_be_bytes(); // 4 bytes
    for i in 0..12 {
        stun_req[8 + i] = unique_id[i % 4];
    }

    socket.send_to(&stun_req, server).await?;
    socket.send_to(b"WHOAMI", server).await?;

    let mut buf = [0u8; 1024];

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > Duration::from_secs(3) {
            return Err(anyhow::anyhow!("Timeout waiting for response"));
        }

        let recv_future = socket.recv_from(&mut buf);
        let (len, _addr) = match tokio::time::timeout(Duration::from_millis(500), recv_future).await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => continue,
        };

        if len > 20 && buf[0] == 0x01 && buf[1] == 0x01 {
            let mut pos = 20;
            while pos + 4 <= len {
                let attr_type = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
                let attr_len = ((buf[pos + 2] as u16) << 8) | (buf[pos + 3] as u16);
                pos += 4;

                if attr_type == 0x0020 {
                    if pos + (attr_len as usize) > len {
                        break;
                    }
                    let x_port = ((buf[pos + 2] as u16) << 8) | (buf[pos + 3] as u16);
                    let x_ip_bytes = &buf[pos + 4..pos + 8];

                    let true_port = x_port ^ 0x2112;
                    let true_ip_u32 = u32::from_be_bytes([
                        x_ip_bytes[0],
                        x_ip_bytes[1],
                        x_ip_bytes[2],
                        x_ip_bytes[3],
                    ]) ^ 0x2112A442;
                    let true_ip = std::net::Ipv4Addr::from(true_ip_u32);

                    return Ok(format!("{}:{}", true_ip, true_port));
                } else if attr_type == 0x0001 {
                    if pos + (attr_len as usize) > len {
                        break;
                    }
                    let port = ((buf[pos + 2] as u16) << 8) | (buf[pos + 3] as u16);
                    let ip = std::net::Ipv4Addr::new(
                        buf[pos + 4],
                        buf[pos + 5],
                        buf[pos + 6],
                        buf[pos + 7],
                    );
                    return Ok(format!("{}:{}", ip, port));
                }

                pos += attr_len as usize;

                let padding = (4 - (attr_len % 4)) % 4;
                pos += padding as usize;
            }

            continue;
        } else if len > 0 && len < 64 {
            let msg = String::from_utf8_lossy(&buf[..len]).to_string();
            if msg.contains('.') && msg.contains(':') && !msg.contains("WHOAMI") {
                return Ok(msg);
            }
        }
    }
}

async fn menu_proxy() -> Result<()> {
    println!("\n--- [Mode 2: UDP Proxy / Hole Punching] ---");

    let bind_port = read_input_u16("Enter LOCAL Bind Port [e.g. 33652]: ").await?;
    let target_port = read_input_u16("Enter TARGET Service Port [e.g. 25565]: ").await?;

    print!("STUN/Echo Server [Default: stun.l.google.com:19302]: ");
    flush_stdout();
    let stun_input = read_line_async().await?;
    let stun_server = if stun_input.trim().is_empty() {
        "stun.l.google.com:19302".to_string()
    } else {
        stun_input.trim().to_string()
    };

    let bind_addr = format!("0.0.0.0:{}", bind_port);
    let public_socket = Arc::new(
        UdpSocket::bind(&bind_addr)
            .await
            .context("Failed to bind public port")?,
    );
    let internal_socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .context("Failed to bind internal socket")?,
    );

    let public_addr_display = match get_public_addr(&public_socket, &stun_server).await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("  Warning: Probe failed ({}), assuming local port.", e);
            format!("(Unknown IP):{}", bind_port)
        }
    };

    println!("\n Proxy Started.");
    println!("------------------------------------------------");
    println!(
        "REAL Public Address : \x1b[32m{}\x1b[0m",
        public_addr_display
    );
    println!("Forwarding to       : 127.0.0.1:{}", target_port);
    println!("Keep-Alive Server   : {}", stun_server);
    println!("------------------------------------------------");
    println!("Press [ENTER] to stop proxy...");

    let target_addr = format!("127.0.0.1:{}", target_port);
    let proxy_task = run_proxy_logic(public_socket, internal_socket, target_addr, stun_server);
    let input_task = read_line_async();

    tokio::select! {
        res = proxy_task => { if let Err(e) = res { eprintln!("Proxy Error: {}", e); } },
        _ = input_task => { println!("Stopping proxy..."); }
    }
    Ok(())
}

async fn run_proxy_logic(
    public_sock: Arc<UdpSocket>,
    internal_sock: Arc<UdpSocket>,
    target_addr: String,
    stun_server: String,
) -> Result<()> {
    let last_client = Arc::new(Mutex::new(None));

    let ka_sock = public_sock.clone();
    let stun_clone_1 = stun_server.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(20)).await;
            let _ = ka_sock.send_to(b"keep-alive", &stun_clone_1).await;
        }
    });

    let p_in = public_sock.clone();
    let i_in = internal_sock.clone();
    let client_ref_in = last_client.clone();
    let target_clone = target_addr.clone();
    let stun_clone_2 = stun_server.clone();

    let t1 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, addr)) = p_in.recv_from(&mut buf).await {
                if addr.to_string() == stun_clone_2 {
                    continue;
                }
                {
                    let mut lock = client_ref_in.lock().await;
                    if lock.is_none() || lock.unwrap() != addr {
                        println!("[New Connection] from {}", addr);
                        *lock = Some(addr);
                    }
                }
                let _ = i_in.send_to(&buf[..len], &target_clone).await;
            }
        }
    });

    let p_out = public_sock.clone();
    let i_out = internal_sock.clone();
    let client_ref_out = last_client.clone();

    let t2 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, _)) = i_out.recv_from(&mut buf).await {
                let lock = client_ref_out.lock().await;
                if let Some(remote_addr) = *lock {
                    let _ = p_out.send_to(&buf[..len], remote_addr).await;
                }
            }
        }
    });

    let _ = tokio::join!(t1, t2);
    Ok(())
}

async fn menu_upnp() -> Result<()> {
    println!("\n--- [Mode 1: UPnP Port Mapping] ---");
    let ext_port = read_input_u16("Enter PUBLIC Port (External) [e.g. 8080]: ").await?;
    let int_port = read_input_u16("Enter LOCAL Port (Internal)  [e.g. 80]: ").await?;
    print!("Protocol (tcp/udp) [default: tcp]: ");
    flush_stdout();
    let proto_str = read_line_async().await?;
    let protocol = if proto_str.trim().eq_ignore_ascii_case("udp") {
        PortMappingProtocol::UDP
    } else {
        PortMappingProtocol::TCP
    };

    println!("\nStep 1: Trying default gateway discovery (Timeout: 3s)...");
    struct DiscoveryResult {
        gateway: igd::Gateway,
        my_ip: IpAddr,
    }

    let first_attempt = tokio::task::spawn_blocking(move || {
        let opts = SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        };
        let gateway = igd::search_gateway(opts)?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(gateway.addr)?;
        Ok::<DiscoveryResult, anyhow::Error>(DiscoveryResult {
            gateway,
            my_ip: socket.local_addr()?.ip(),
        })
    })
    .await?;

    let result = match first_attempt {
        Ok(res) => res,
        Err(_) => {
            println!("\n  Default discovery failed.");
            println!("Select the Network Interface connected to your Router:");
            let interfaces = if_addrs::get_if_addrs()?
                .into_iter()
                .filter(|i| !i.is_loopback() && i.addr.ip().is_ipv4())
                .collect::<Vec<_>>();
            if interfaces.is_empty() {
                return Err(anyhow::anyhow!("No network interfaces found"));
            }
            for (i, iface) in interfaces.iter().enumerate() {
                println!("{}. {} ({})", i + 1, iface.addr.ip(), iface.name);
            }
            let idx = read_input_u16("\nSelect: ").await? as usize;
            if idx == 0 || idx > interfaces.len() {
                return Err(anyhow::anyhow!("Invalid selection"));
            }
            let selected_ip = interfaces[idx - 1].addr.ip();
            tokio::task::spawn_blocking(move || {
                let opts = SearchOptions {
                    timeout: Some(Duration::from_secs(5)),
                    bind_addr: SocketAddrV4::new(
                        match selected_ip {
                            IpAddr::V4(ip) => ip,
                            _ => unreachable!(),
                        },
                        0,
                    )
                    .into(),
                    ..Default::default()
                };
                let gateway = igd::search_gateway(opts)?;
                Ok::<DiscoveryResult, anyhow::Error>(DiscoveryResult {
                    gateway,
                    my_ip: selected_ip,
                })
            })
            .await??
        }
    };

    let gateway = result.gateway;
    let my_final_ip = result.my_ip;
    let local_addr = SocketAddrV4::new(
        match my_final_ip {
            IpAddr::V4(ip) => ip,
            _ => panic!(),
        },
        int_port,
    );
    println!("Found Gateway: {}\nMy Local IP: {}", gateway, my_final_ip);

    let gateway_add = gateway.clone();
    tokio::task::spawn_blocking(move || {
        gateway_add.add_port(protocol, ext_port, local_addr, 0, "Rust_Tool")
    })
    .await??;

    println!("\n SUCCESS! Mapping is ACTIVE.");
    println!(
        "External Access: {}:{}",
        gateway.get_external_ip()?,
        ext_port
    );
    println!("Press [ENTER] to stop mapping...");
    read_line_async().await?;
    let _ = tokio::task::spawn_blocking(move || gateway.remove_port(protocol, ext_port)).await??;
    Ok(())
}

async fn menu_server() -> Result<()> {
    let port = read_input_u16("Enter Bind Port [default: 8000]: ").await?;
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    println!("\n Server Listening on 0.0.0.0:{}", port);
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            res = socket.recv_from(&mut buf) => {
                if let Ok((_, src)) = res {
                    let _ = socket.send_to(src.to_string().as_bytes(), src).await;
                }
            },
            _ = read_line_async() => { break; }
        }
    }
    Ok(())
}

async fn read_line_async() -> Result<String> {
    let mut line = String::new();
    let _ = io::BufReader::new(io::stdin()).read_line(&mut line).await;
    Ok(line)
}
async fn read_input_u16(prompt: &str) -> Result<u16> {
    loop {
        print!("{}", prompt);
        flush_stdout();
        if let Ok(line) = read_line_async().await {
            if let Ok(n) = line.trim().parse::<u16>() {
                return Ok(n);
            }
        }
    }
}
async fn wait_for_enter() {
    let _ = read_line_async().await;
}
fn flush_stdout() {
    let _ = stdout().flush();
}
fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}
