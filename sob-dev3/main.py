import os
import json
import time
import hashlib
import struct

# Function to encode an integer using Bitcoin's varint encoding
def varint_encoding(value: int) -> bytes:
    if value < 0xfd:
        return value.to_bytes(1, 'little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    return b'\xff' + value.to_bytes(8, 'little')

# Function to perform double SHA-256 hash
def hash_double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# Function to compute the Merkle root from a list of transaction hashes
def calculate_merkle_root(hex_list: list[str]) -> str:
    if not hex_list:
        return '0' * 64
    layer = [bytes.fromhex(item)[::-1] for item in hex_list]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])  # Duplicate the last element if odd number of elements
        layer = [hash_double_sha256(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0][::-1].hex()

# Function to get the Witness Transaction ID (wtxid)
def get_wtxid(tx_hex: str) -> str:
    return hash_double_sha256(bytes.fromhex(tx_hex))[::-1].hex()

# Function to construct a Coinbase Transaction ID from non-witness data
def construct_coinbase_txid(non_witness_tx: bytes) -> str:
    return hash_double_sha256(non_witness_tx)[::-1].hex()

# Function to create a coinbase transaction
def create_coinbase_transaction(block_reward: int, witness_commitment: str, witness_nonce: bytes = b'\x00'*32) -> tuple[bytes, str]:
    version = struct.pack('<I', 1)
    marker, flag = b'\x00', b'\x01'
    in_count = varint_encoding(1)
    prev_hash = b'\x00' * 32
    prev_index = struct.pack('<I', 0xffffffff)
    script_sig = b'coinbase'
    script_sig_len = varint_encoding(len(script_sig))
    sequence = b'\xff\xff\xff\xff'
    out_count = varint_encoding(2)
    locktime = struct.pack('<I', 0)
    
    # First output: Block reward to miner
    value1 = struct.pack('<Q', block_reward)
    script_pubkey1 = bytes.fromhex('0014' + '0'*40)
    script_pubkey1_len = varint_encoding(len(script_pubkey1))

    # Second output: Witness commitment
    value2 = struct.pack('<Q', 0)
    witness_script = bytes.fromhex('6a24aa21a9ed' + witness_commitment)  # Using working witness logic
    script_pubkey2_len = varint_encoding(len(witness_script))
    
    # Witness data
    witness_data = varint_encoding(1) + varint_encoding(len(witness_nonce)) + witness_nonce

    # Construct full transaction
    tx = (
        version + marker + flag + in_count + prev_hash + prev_index +
        script_sig_len + script_sig + sequence + out_count +
        value1 + script_pubkey1_len + script_pubkey1 +
        value2 + script_pubkey2_len + witness_script +
        witness_data + locktime
    )
    
    return tx, hash_double_sha256(tx)[::-1].hex()

# Function to mine a new block
def mine_new_block(transactions: list[dict]) -> tuple[str, str, list[str]]:
    MAX_BLOCK_WEIGHT = 4_000_000
    COINBASE_WEIGHT_ESTIMATE = 400
    selected_transactions = []
    current_weight = 0
    
    # Select transactions based on highest fee/weight ratio
    for tx in sorted(transactions, key=lambda x: -x['fee'] / x['weight']):
        if current_weight + tx['weight'] <= MAX_BLOCK_WEIGHT - COINBASE_WEIGHT_ESTIMATE:
            selected_transactions.append(tx)
            current_weight += tx['weight']
    
    # Calculate block rewards
    total_fees = sum(tx['fee'] for tx in selected_transactions)
    block_reward = 625000000 + total_fees  # Block subsidy + fees
    
    # Compute witness merkle root
    mempool_wtxids = [get_wtxid(tx['hex']) for tx in selected_transactions]
    wtxid_list = ["0"*64] + mempool_wtxids
    witness_merkle_root = calculate_merkle_root(wtxid_list)
    
    # Witness commitment logic (From friend's code)
    commitment_hash = hash_double_sha256(bytes.fromhex(witness_merkle_root)[::-1] + b'\x00' * 32).hex()
    
    # Create coinbase transaction with correct witness commitment
    coinbase_tx, coinbase_txid = create_coinbase_transaction(block_reward, commitment_hash)
    
    # Generate Merkle root of the block
    block_txids = [coinbase_txid] + [tx['txid'] for tx in selected_transactions]
    merkle_root = calculate_merkle_root(block_txids)
    
    # Construct block header
    header_template = (
        struct.pack('<I', 0x20000000) +  # Version
        b'\x00' * 32 +  # Previous block hash (set to zero for simplicity)
        bytes.fromhex(merkle_root)[::-1] +  # Merkle root
        struct.pack('<I', int(time.time())) +  # Timestamp
        struct.pack('<I', 0x1f00ffff)  # Target difficulty (simplified)
    )
    
    # Proof-of-Work target
    target = bytes.fromhex('0000ffff' + '00'*28)
    target_value = int.from_bytes(target, 'big')
    nonce = 0
    
    # Mining loop (brute-force nonce)
    while nonce < 0x100000000:
        header = header_template + struct.pack('<I', nonce)
        block_hash = hash_double_sha256(header)[::-1]
        if int.from_bytes(block_hash, 'big') < target_value:
            break
        nonce += 1
    
    return header.hex(), coinbase_tx.hex(), block_txids

# Function to fetch transactions from mempool
def fetch_transactions(mempool_directory: str) -> list[dict]:
    tx_data = []
    for filename in sorted(os.listdir(mempool_directory)):
        if not filename.endswith('.json'):
            continue
        file_path = os.path.join(mempool_directory, filename)
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                if isinstance(data, dict) and all(key in data for key in ['txid', 'fee', 'weight', 'hex']):
                    tx_data.append(data)
                elif isinstance(data, list):
                    for tx in data:
                        if all(key in tx for key in ['txid', 'fee', 'weight', 'hex']):
                            tx_data.append(tx)
        except:
            continue
    return tx_data

# Main function
def main():
    script_directory = os.path.dirname(os.path.abspath(__file__))
    mempool_directory = os.path.join(script_directory, "..", "mempool")
    
    # Ensure mempool directory exists
    if not os.path.exists(mempool_directory):
        print(f"Error: Mempool directory '{mempool_directory}' not found.")
        return
    
    transaction_list = fetch_transactions(mempool_directory)
    
    # Mine the new block
    header, coinbase_tx, txid_list = mine_new_block(transaction_list)
    
    output_file = os.path.join(script_directory, "..", "out.txt")
    with open(output_file, 'w') as output:
        output.write(header + '\n')
        output.write(coinbase_tx + '\n')
        for txid in txid_list:
            output.write(txid + '\n')

if __name__ == '__main__':
    main()
