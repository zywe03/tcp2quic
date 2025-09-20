mod client;
mod common;
mod server;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::exit;

const USAGE: &str = concat!(
    "usage: tcp2quic <mode> <local_addr> <remote_addr> <options>\n",
    "\n",
    "tcp2quic -c <local_addr> <remote_addr> <options>\n",
    "tcp2quic -s <local_addr> <remote_addr> <options>"
);

enum Mode {
    Client,
    Server,
}

struct Config {
    mode: Mode,
    local: SocketAddr,
    remote: SocketAddr,
    hostname: String,
    insecure: bool,
}

impl Config {
    fn from_args() -> Self {
        let args: Vec<String> = env::args().collect();
        if args.len() != 5 {
            eprintln!("{}", USAGE);
            exit(1);
        }
        let mode = match args[1].as_str() {
            "-s" => Mode::Server,
            "-c" => Mode::Client,
            _ => {
                eprintln!("{}", USAGE);
                exit(1);
            }
        };

        let (hostname, insecure) = parse_config(&args[4]);

        Config {
            mode,
            local: args[2]
                .to_socket_addrs()
                .expect("invalid local addr")
                .next()
                .unwrap(),
            remote: args[3]
                .to_socket_addrs()
                .expect("invalid remote addr")
                .next()
                .unwrap(),
            hostname,
            insecure,
        }
    }
}

// 配置解析
macro_rules! has_opt {
    ($it: expr, $name: expr) => {
        $it.find(|&kv| kv == $name).is_some()
    };
    ($s: expr => $name: expr) => {
        has_opt!($s.split(';').map(|x| x.trim()), $name)
    };
}

macro_rules! get_opt {
    ($it: expr, $name: expr) => {
        $it.find(|kv| kv.starts_with($name))
            .and_then(|kv| kv.split_once("="))
            .map(|(_, v)| v.trim())
            .and_then(|v| if v.is_empty() { None } else { Some(v) })
    };
    ($s: expr => $name: expr) => {
        get_opt!($s.split(';').map(|x| x.trim()), $name)
    };
}


fn parse_config(config_str: &str) -> (String, bool) {
    let hostname = get_opt!(config_str => "sni")
        .or_else(|| get_opt!(config_str => "servername"))
        .unwrap_or("localhost")
        .to_string();

    let insecure = has_opt!(config_str => "insecure");

    (hostname, insecure)
}

#[tokio::main]
async fn main() {
    let c = Config::from_args();
    if let Err(e) = match c.mode {
        Mode::Client => client::run(c.local, c.remote, c.hostname, c.insecure).await,
        Mode::Server => server::run(c.local, c.remote, c.hostname).await,
    } {
        eprintln!("Error: {}", e);
        exit(1);
    }
}
