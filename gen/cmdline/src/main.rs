use clap::Parser;
#[derive(Parser, Debug)]
struct Args{
    #[arg(short, long)]
    inp1: String,
    //#[arg(short, long)]
    inp2: String,
}
fn main() {
    let args = Args::parse();
    println!("{}", args.inp1);
    println!("{}", args.inp2);
    println!("Hello, world!");
}
