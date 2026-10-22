use transmission::create_key_pair;

fn main() {
    let (private, public) = create_key_pair();
    println!("Public key:  {}", public);
    println!("Private key: {}", private);
}
