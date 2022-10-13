use halo2_proofs::poly::commitment::Params;
use plonk_verifier::system::halo2::aggregation::gen_srs;
use std::{
    fs::{self, File},
    io::BufWriter,
};

fn main() {
    let dir = "./params";
    fs::create_dir_all(dir).unwrap();

    const K: u32 = 23;
    let mut params = gen_srs(K);
    for k in (15..K).rev() {
        params.downsize(k);
        let path = format!("{}/kzg_bn254_{}.srs", dir, k);
        params.write(&mut BufWriter::new(File::create(path).unwrap())).unwrap();
    }
}
