use clap::{Parser, Subcommand};
use std::{net::IpAddr, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "fleetops-cli",
    version,
    about = "Reach a pod's port through FleetOps"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen locally and forward each connection to a pod's port. Copy the
    /// command from a pod's Port-forward dialog in FleetOps.
    Forward {
        /// FleetOps's address, e.g. https://fleet.example.com
        #[arg(long, env = "FLEETOPS_SERVER")]
        server: String,
        /// The fpt_… link from the Port-forward dialog (single use, 5 minutes).
        ticket: String,
        /// Local port; defaults to the pod's port, 0 picks a free one.
        #[arg(long)]
        local: Option<u16>,
        /// Local address to listen on.
        #[arg(long, default_value = "127.0.0.1")]
        address: IpAddr,
        /// A PEM CA certificate to trust, for a server with its own certificate.
        #[arg(long, env = "FLEETOPS_CA")]
        ca: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let Command::Forward {
        server,
        ticket,
        local,
        address,
        ca,
    } = Cli::parse().command;
    let args = fleetops_cli::forward::ForwardArgs {
        server,
        ticket,
        local,
        address,
        ca,
    };
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match fleetops_cli::forward::run(args, ctrl_c).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
