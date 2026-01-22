from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# Set up RPC connection
RPC_URL = "http://alice:password@127.0.0.1:18443"
rpc = AuthServiceProxy(RPC_URL)

# Test connection
try:
    info = rpc.getblockchaininfo()
    print("Connected to Bitcoin node successfully!")
    print(info)
except JSONRPCException as e:
    print(f"RPC error: {e}")

# Create or load the wallet
wallet_name = "testwallet"
wallets = rpc.listwalletdir()["wallets"]
wallet_names = [w["name"] for w in wallets]

if wallet_name not in wallet_names:
    rpc.createwallet(wallet_name)
    print(f"Wallet '{wallet_name}' created.")
else:
    print(f"Wallet '{wallet_name}' already exists.")

# Unload the wallet if it's already loaded
try:
    rpc.unloadwallet(wallet_name)
    print(f"Wallet '{wallet_name}' unloaded.")
except JSONRPCException as e:
    print(f"Wallet '{wallet_name}' is not loaded or does not exist: {e}")

# Load the wallet
rpc.loadwallet(wallet_name)
rpc = AuthServiceProxy(f"{RPC_URL}/wallet/{wallet_name}")

# Generate a new address
new_address = rpc.getnewaddress()
print(f"New Address: {new_address}")

# Mine 101 blocks to activate funds
rpc.generatetoaddress(101, new_address)
print("Mined 101 blocks.")

# Check wallet balance
balance = rpc.getbalance()
print(f"Wallet balance: {balance} BTC")

# Mine additional blocks if balance is insufficient
if balance < 100:
    rpc.generatetoaddress(101, new_address)
    print("Mined 101 additional blocks.")
    balance = rpc.getbalance()
    print(f"Updated wallet balance: {balance} BTC")

# Define outputs
recipient_address = "bcrt1qq2yshcmzdlznnpxx258xswqlmqcxjs4dssfxt2"
amount_to_send = 100  # BTC
op_return_data = "We are all Satoshi!!"

# Convert OP_RETURN message to hex
op_return_hex = op_return_data.encode('utf-8').hex()
op_return_script = f"6a{len(op_return_data):02x}{op_return_hex}"

# Create transaction
tx = rpc.createrawtransaction(
    [],  # No inputs, Bitcoin Core selects them
    [
        {recipient_address: amount_to_send},
        {"data": op_return_hex}  # OP_RETURN output
    ]
)

# Fund the transaction
funded_tx = rpc.fundrawtransaction(tx, {"fee_rate": 21})

# Sign the transaction
signed_tx = rpc.signrawtransactionwithwallet(funded_tx["hex"])

# Broadcast the transaction
txid = rpc.sendrawtransaction(signed_tx["hex"])

print(f"Transaction sent! TXID: {txid}")

# Save transaction ID to out.txt
with open("out.txt", "w") as f:
    f.write(txid)

print("Transaction ID saved to out.txt.")