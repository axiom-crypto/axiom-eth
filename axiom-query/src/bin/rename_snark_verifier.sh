#!/bin/bash

# Check if a file name is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <solidity filename>"
    exit 1
fi

# File to be modified
FILE="$1"

new_file="AxiomV2QueryVerifier.sol"

# The first and third lines are empty
# Remove the first and third line from the file
sed '1d;3d' $FILE > $new_file

# Replace 'contract Halo2Verifier' with 'contract AxiomV2QueryVerifier'
sed 's/contract Halo2Verifier/contract AxiomV2QueryVerifier/g' $new_file > $new_file.tmp && mv $new_file.tmp $new_file

echo "Modifications complete. Written to $new_file"

echo "To diff is:"
diff $FILE $new_file

echo "Running forge fmt on $new_file"
forge fmt $new_file
