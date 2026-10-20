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
}
