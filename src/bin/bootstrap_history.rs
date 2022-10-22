use ark_std::{end_timer, start_timer};
use clap::Parser;
use halo2_mpt::eth::eth::aggregation::{self, FULL_DEPTH};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long = "last-block")]
    last_block: String,
}

fn main() {
    let args = Cli::parse();
    let mut block_number = if args.last_block.starts_with("0x") {
        u64::from_str_radix(&args.last_block[2..], 16).expect("Enter proper hex")
    } else {
        u64::from_str_radix(&args.last_block, 10)
            .expect("Block number needs to be base 10 or in hex with 0x prefix")
    };

    while block_number >= (1 << FULL_DEPTH) - 1 {
        let batch_timer = start_timer!(|| format!(
            "Aggregating blocks {:06x} -> {:06x} inclusive",
            block_number,
            block_number - ((1 << FULL_DEPTH) - 1)
        ));

        aggregation::run(block_number, false);

        end_timer!(batch_timer);
        block_number -= 1 << FULL_DEPTH;
    }
}
