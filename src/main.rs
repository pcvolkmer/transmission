use bcrypt::DEFAULT_COST;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::Password;
use std::error::Error;
use std::io;
use std::io::Read;
use transmission::{create_key_pair, create_pub_key};

#[derive(Parser)]
#[command(author, version, about)]
#[command(arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    cmd: SubCommand,
    #[arg(
        short = 'v',
        global = true,
        help = "Show more, e.g. key pair instead of printing private key only"
    )]
    v: bool,
}

#[derive(Subcommand)]
enum SubCommand {
    #[command(about = "Generates a new private key and writes it to stdout")]
    Genkey,
    #[command(about = "Reads a private key from stdin and writes a public key to stdout")]
    Pubkey,
    #[command(about = "Generates BCrypt credentials for Agents Proxy-Authentication")]
    ProxyAuth { username: String },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        SubCommand::Genkey => {
            let (private, public) = create_key_pair();
            if cli.v {
                println!("{} {public}", style("Public key: ").bold());
                println!("{} {private}", style("Private key:").bold());
            } else {
                println!("{private}");
            }
        }
        SubCommand::Pubkey => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let public = create_pub_key(&input.replace('\n', ""))?;
            println!("{public}");
        }
        SubCommand::ProxyAuth { username } => {
            let password = Password::new()
                .with_prompt("New Password")
                .with_confirmation("Confirm password", "Passwords mismatching")
                .interact()?;
            let hash = bcrypt::hash(password, DEFAULT_COST)?;
            println!("{username}:{hash}");
        }
    }

    Ok(())
}
