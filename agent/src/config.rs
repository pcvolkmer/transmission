use clap::Parser;
use reqwest::{Method, Url};
use serde::Deserialize;
use std::io::Error;
use std::path::PathBuf;
use transmission::create_shared_secret;

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
    proxy_authorization: Option<String>,
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

impl Destination {
    pub fn get_host(&self) -> Option<String> {
        let url = Url::parse(&self.base_url).ok()?;
        let host = url.host()?.to_string();
        Some(host)
    }
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
        format!("{}/_events/{}", self.peer.url, self.destination.name)
    }

    pub fn pending_url_for(&self, uuid: &str) -> String {
        format!(
            "{}/_pending/{}/{}",
            self.peer.url, self.destination.name, uuid
        )
    }

    pub fn shared_secret(&self, salt: &str) -> Result<[u8; 32], Error> {
        create_shared_secret(&self.secret(), &self.other_public(), salt)
    }

    pub fn proxy_credentials(&self) -> Option<(String, String)> {
        if let Some(proxy_authorization) = self.agent.proxy_authorization.clone() {
            return proxy_authorization
                .split_once(':')
                .map(|(a, b)| (a.to_string(), b.to_string()));
        }

        None
    }
}
