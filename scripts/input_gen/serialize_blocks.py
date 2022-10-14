import argparse
import json
import pprint
import copy

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
    block_hashes = []
    for block_number in block_numbers:
        block = infura.eth.get_block(block_number)
        block_rlp = get_block_rlp(block)
        blocks.append(block_rlp)
        if block_number == block_numbers[0]:
            block_hashes.append(block['parentHash'].hex()[2:])
        block_hashes.append(block['hash'].hex()[2:])
    return (blocks, block_hashes)

def concat(a, b):
    be = bytearray.fromhex(a) + bytearray.fromhex(b)
    return be.hex()

def hash_tree_root(leaves):
    depth = len(leaves).bit_length() - 1
    assert(1 << depth == len(leaves))
    hashes = []
    for x in range(1 << (depth-1)):
        hash = keccak256(concat(leaves[2 * x], leaves[2*x+1]))
        hashes.append(hash)
    for d in range(depth - 2, -1, -1):
        for x in range(1 << d):
            hashes[x] = keccak256(concat(hashes[2*x], hashes[2*x+1]))
    return hashes[0]

def create_merkle_proof(leaves, idx):
    depth = len(leaves).bit_length() - 1
    hashes = copy.deepcopy(leaves)
    proof = []
    for i in range(depth):
        side = idx >> i
        proof.append(hashes[side ^ 1])
        for x in range(0, 1 << (depth-i), 2):
            hashes[x//2] = keccak256(concat(hashes[x], hashes[x+1]))
    return proof, hashes[0]

def check_merkle_proof(hash, root, proof, side):
    curr = copy.deepcopy(hash)
    for i in range(len(proof)):
        if side & 1 == 0:
            curr = keccak256(concat(curr, proof[i]))
        else:
            curr = keccak256(concat(proof[i], curr))
        side = side >> 1
    assert(curr == root)

def create_block_proof(lastBlockNumber, side):
    with open('INFURA_ID', 'r') as f:
        infura_id = f.read()
    infura = Web3(HTTPProvider("https://goerli.infura.io/v3/{}".format(infura_id)))
    block_hashes = []
    for block_number in range(lastBlockNumber - 1024 + 1, lastBlockNumber + 1):
        block = infura.eth.get_block(block_number)
        block_hashes.append(block['hash'].hex()[2:])
    proof, root = create_merkle_proof(block_hashes, side)
    check_merkle_proof(block_hashes[side], root, proof, side)
    print("publicHash: ", '0x' + block_hashes[1023])
    print("blockHash: ", '0x' + block_hashes[side])
    proof = ['0x' + x for x in proof]
    print("merkleProof:")
    print(proof)
    print("side: ", side)

def main():
    start_block_number = 0xef0018
    num_blocks = 8
    (blocks, block_hashes) = get_block_rlp_list([x for x in range(start_block_number, start_block_number + num_blocks)])

    merkle_root = hash_tree_root(block_hashes[1:])

    with open('headers/{:06x}_{}.json'.format(start_block_number + num_blocks - 1, num_blocks), 'w') as f:
        f.write(json.dumps(blocks))
    with open('headers/{:06x}_{}_instances.json'.format(start_block_number + num_blocks - 1, num_blocks), 'w') as f:
        f.write(json.dumps([block_hashes[0], block_hashes[len(block_hashes) - 1], merkle_root]))

if __name__ == '__main__':
    main()
