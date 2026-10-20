use clap::Parser;
use reqwest::Method;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    agent: Agent,
    peer: Peer,
    destination: Destination,
}

#[derive(Debug, Deserialize)]
pub struct Agent {
    allowed_methods: Vec<String>,
    private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct Peer {
    url: String,
    public_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Destination {
    pub name: String,
    pub base_url: String,
}

impl Config {
    pub fn parse() -> Result<Self, ()> {
        let cli = Cli::parse();
        let contents = std::fs::read_to_string(&cli.config).map_err(|_| ())?;
        let config = toml::from_str::<Config>(&contents);
        Ok(config.map_err(|_| ())?)
    }

    pub fn is_method_allowed(&self, method: &Method) -> bool {
        self.agent
            .allowed_methods
            .iter()
            .any(|m| m.to_ascii_lowercase() == method.to_string().to_ascii_lowercase())
    }

    pub fn destination(&self) -> Destination {
        self.destination.clone()
    }

    pub fn secret(&self) -> String {
        self.agent.private_key.clone()
    }

    pub fn other_public(&self) -> String {
        self.peer.public_key.clone()
    }

    pub fn sse_url(&self) -> String {
        format!("{}/events/{}", self.peer.url, self.destination.name)
    }

    pub fn pending_url_for(&self, uuid: &str) -> String {
        format!(
            "{}/pending/{}/{}",
            self.peer.url, self.destination.name, uuid
        )
    }
}
