use clap::Parser;

fn main() {
    match agent_creds::cli::run(agent_creds::cli::Cli::parse()) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("agent-creds: {error}");
            std::process::exit(1);
        }
    }
}
