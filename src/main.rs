use clap::Parser;

fn main() -> anyhow::Result<()> {
    shb::run(shb::Args::parse())
}
