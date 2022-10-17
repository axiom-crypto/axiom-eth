#!/bin/bash

ID_FILE="./INFURA_ID"
INFURA_ID=$(cat "$ID_FILE")

curl -X POST --header "Content-Type: application/json" --data '{"id":1, "jsonrpc": "2.0", "method":"eth_getBlockByNumber","params": ["latest", true]}' https://mainnet.infura.io/v3/"$INFURA_ID" | node -r fs -e 'console.log(JSON.stringify(JSON.parse(fs.readFileSync("/dev/stdin", "utf-8"))["result"], null, 4));' > block.json 
curl -X POST --header "Content-Type: application/json" --data @query_test_storage.json https://mainnet.infura.io/v3/"$INFURA_ID" | node -r fs -e 'console.log(JSON.stringify(JSON.parse(fs.readFileSync("/dev/stdin", "utf-8"))["result"], null, 4));' > acct_storage_pf.json