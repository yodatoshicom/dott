use clap::Parser;

#[derive(Parser)]
#[command(name = "dott", version, about = "private domain search. no middlemen.")]
pub struct Cli {
    pub name: Option<String>,
    #[arg(short, long)]
    pub tlds: Option<String>,
    #[arg(short, long, num_args = 1..)]
    pub suggest: Option<Vec<String>>,
    #[arg(long)]
    pub plain: bool,
    #[arg(long, value_name = "DOMAIN")]
    pub watch: Option<String>,
    #[arg(long, value_name = "DOMAIN")]
    pub unwatch: Option<String>,
    #[arg(long)]
    pub watching: bool,
    #[arg(long, hide = true)]
    pub background_check: bool,
}
