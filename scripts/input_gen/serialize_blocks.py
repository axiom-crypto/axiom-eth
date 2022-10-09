import argparse
import json
import pprint

import mpt
import rlp
import sha3

from web3 import Web3, HTTPProvider

from mpt import MerklePatriciaTrie

def keccak256(x):
    k = sha3.keccak_256()
    k.update(bytearray.fromhex(x))
    return k.hexdigest()

def get_block_rlp(block):
    block_list = [
        bytearray(block['parentHash']),
        bytearray(block['sha3Uncles']),
        bytearray.fromhex(block['miner'][2:]),
        bytearray(block['stateRoot']),
        bytearray(block['transactionsRoot']),
        bytearray(block['receiptsRoot']),
        bytearray(block['logsBloom']),
        block['difficulty'],
        block['number'],
        block['gasLimit'],
        block['gasUsed'],
        block['timestamp'],
        bytearray(block['extraData']),
        bytearray(block['mixHash']),
        bytearray(block['nonce']),
        block['baseFeePerGas']
    ]
    rlp_block = rlp.encode(block_list).hex()
    return rlp_block

def get_block_rlp_list(block_numbers):
    with open('INFURA_ID', 'r') as f:
        infura_id = f.read()
    infura = Web3(HTTPProvider("https://mainnet.infura.io/v3/{}".format(infura_id)))
    blocks = []
    for block_number in block_numbers:
        block = infura.eth.get_block(block_number)
        block_rlp = get_block_rlp(block)
        blocks.append(block_rlp)
    return blocks

def main():
    start_block_number = 0xef0000
    num_blocks = 32
    blocks = get_block_rlp_list([x for x in range(start_block_number, start_block_number + num_blocks)])

    with open('headers/{:06x}_{}.json'.format(start_block_number + num_blocks - 1, num_blocks), 'w') as f:
        f.write(json.dumps(blocks))

if __name__ == '__main__':
    main()
