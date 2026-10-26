use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    proxy: Proxy,
    peers: Vec<Agent>,
}

#[derive(Debug, Deserialize)]
pub struct Proxy {
    listen: String,
    post_max_size: Option<String>,
    private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct Agent {
    destination: String,
    pub public_key: String,
    pub shared_secret: String,
}

impl Config {
    pub fn parse() -> Result<Self, ()> {
        let cli = Cli::parse();
        let contents = std::fs::read_to_string(&cli.config).map_err(|_| ())?;
        let config = toml::from_str::<Config>(&contents);
        Ok(config.map_err(|_| ())?)
    }

    pub fn secret(&self) -> String {
        self.proxy.private_key.clone()
    }

    pub fn agent(&self, destination: &str) -> Option<&Agent> {
        self.peers
            .iter()
            .find(|agent| agent.destination == destination)
            .take()
    }

    pub fn listen(&self) -> String {
        self.proxy.listen.clone()
    }

    pub fn post_max_size(&self) -> u64 {
        let default_size = 8 * 1024 * 1024;

        if let Some(post_max_size) = &self.proxy.post_max_size
            && let Ok(post_max_size) = byte_unit::Byte::parse_str(post_max_size, true)
        {
            return post_max_size.as_u64();
        }

        default_size
    }
}
