#!/bin/bash

for k in {5..23} # 25}
do
    wget "https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${k}.srs"
done

mv *.srs params/
