#!/bin/bash

# Check if a file name is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <solidity filename>"
    exit 1
fi

# File to be modified
FILE="$1"

# The first and third line are empty
# Remove the first and third line from the file
sed '1d;3d' $FILE > "$FILE.0"

base_name=$(basename $FILE)
if [ $base_name == "39cb264c605428fc752e90b6ac1b77427ab06b795419a759e237e283b95f377f.sol" ]; then
    # Replace 'contract Halo2Verifier' with 'contract AxiomV2CoreVerifier'
    new_file="AxiomV2CoreVerifier.sol"
    sed "s/contract Halo2Verifier/contract AxiomV2CoreVerifier/g" "$FILE.0" > $new_file
    rm -f $FILE.0
elif [ $base_name == "0379c723deafac09822de4f36da40a5595331c447a5cc7c342eb839cd199be02.sol" ]; then
    # Replace 'contract Halo2Verifier' with 'contract AxiomV2CoreHistoricalVerifier'
    new_file="AxiomV2CoreHistoricalVerifier.sol"
    sed "s/contract Halo2Verifier/contract AxiomV2CoreHistoricalVerifier/g" "$FILE.0" > $new_file
else
    echo "Unknown file"
    exit 1
fi

echo "Modifications complete. New file output to $new_file"
rm -f "$FILE.0"

echo "To diff is:"
diff $FILE $new_file

echo "Running forge fmt on $new_file"
forge fmt $new_file
