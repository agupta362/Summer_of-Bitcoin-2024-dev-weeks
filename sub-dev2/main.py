# Import required libraries for cryptographic operations, data serialization, and base58 encoding
import hashlib
import struct
import base58
import ecdsa
from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa.curves import SECP256k1

class P2SH_P2WSH_Transaction:
    """Represents a Bitcoin transaction using P2SH-P2WSH (Pay-to-Script-Hash wrapped Pay-to-Witness-Script-Hash)"""
    
    def __init__(self):
        # Transaction configuration
        self.tx_version = 2                  # Transaction version (SegWit uses version 2)
        self.locktime = 0                     # Locktime for transaction
        self.prev_transaction = bytes.fromhex("00" * 32)  # Previous transaction hash (32-byte null for example)
        self.prev_output_index = 0            # Previous output index
        self.sequence_number = 0xFFFFFFFF      # Sequence number (max value for no RBF)
        self.amount_sats = 100_000             # Amount being spent in satoshis (0.001 BTC)
        self.recipient_address = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"  # Recipient P2SH address

        # Signer configuration (testnet keys for demonstration)
        self.priv_keys = [
            bytes.fromhex("39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf"),
            bytes.fromhex("5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d")
        ]

        # Witness script (2-of-2 multisig in this example)
        self.witness_script = bytes.fromhex(
            "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b"
            "21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"
        )

        # Public keys in script order (must match witness script ordering)
        self.pubkey_ordered = [
            bytes.fromhex("032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b"),
            bytes.fromhex("039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd56")
        ]

    @staticmethod
    def hash256(data: bytes) -> bytes:
        """Double SHA-256 hash used throughout Bitcoin protocols"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @staticmethod
    def base58_decode(addr: str) -> bytes:
        """Decode Base58Check address and return hash without version byte"""
        decoded = base58.b58decode_check(addr)
        return decoded[1:]  # Strip version byte (P2SH uses 0x05 but address encodes it)

    def sighash_preimage(self) -> bytes:
        """Constructs signature preimage according to BIP143 (SegWit sighash algorithm)"""
        
        # Calculate hashPrevouts and hashSequences (not used here but included for BIP143 compliance)
        hash_prevouts = self.hash256(self.prev_transaction + struct.pack("<L", self.prev_output_index))
        hash_sequences = self.hash256(struct.pack("<L", self.sequence_number))
        
        # Prepare output being created (P2SH script)
        p2sh_script = b'\xa9\x14' + self.base58_decode(self.recipient_address) + b'\x87'  # OP_HASH160 <hash> OP_EQUAL
        hash_outputs = self.hash256(struct.pack("<Q", self.amount_sats) + bytes([len(p2sh_script)]) + p2sh_script)
        
        # Script code for P2WSH is the witness script itself
        script_code = bytes([len(self.witness_script)]) + self.witness_script

        # Build preimage following BIP143 specification
        preimage = (
            struct.pack("<L", self.tx_version) +  # Version
            hash_prevouts +                       # hashPrevouts
            hash_sequences +                      # hashSequence
            self.prev_transaction +               # Previous transaction ID
            struct.pack("<L", self.prev_output_index) +  # Previous output index
            script_code +                         # Script code (witness script)
            struct.pack("<Q", self.amount_sats) + # Input amount
            struct.pack("<L", self.sequence_number) + # Sequence number
            hash_outputs +                        # hashOutputs
            struct.pack("<L", self.locktime) +     # Locktime
            struct.pack("<L", 1)                  # SIGHASH_ALL
        )
        return preimage

    def generate_signature(self, msg_hash: bytes) -> list:
        """Generate ECDSA signatures in required order using private keys"""
        signatures = {}
        
        for idx, private_key in enumerate(self.priv_keys):
            # Create signing key and derive public key
            signing_key = ecdsa.SigningKey.from_string(private_key, curve=SECP256k1)
            pubkey = signing_key.get_verifying_key().to_string("compressed")

            # Create deterministic signature using RFC6979
            sig = signing_key.sign_digest_deterministic(
                msg_hash, hashfunc=hashlib.sha256, sigencode=sigencode_der
            )
            
            # Enforce low-S value to prevent transaction malleability
            r, s = sigdecode_der(sig, SECP256k1.order)
            if s > SECP256k1.order // 2:
                s = SECP256k1.order - s
                sig = sigencode_der(r, s, SECP256k1.order)

            # Append SIGHASH_ALL byte
            final_signature = sig + b'\x01'

            # Store signatures according to public key order in witness script
            if pubkey == self.pubkey_ordered[0]:
                signatures[1] = final_signature  # First signature position
            else:
                signatures[2] = final_signature  # Second signature position

        # Return signatures in script order [sig1, sig2]
        return [signatures[1], signatures[2]]

    def construct_transaction(self) -> bytes:
        """Build complete signed transaction in raw bytes format"""
        
        # Create witness program (P2WSH) for scriptSig
        witness_program = b'\x00\x20' + hashlib.sha256(self.witness_script).digest()
        script_sig = bytes([len(witness_program)]) + witness_program  # Redeem script for P2SH
        
        # Create output script (P2SH)
        p2sh_script = b'\xa9\x14' + self.base58_decode(self.recipient_address) + b'\x87'  # OP_HASH160 <hash> OP_EQUAL
        output_script = bytes([len(p2sh_script)]) + p2sh_script

        # Build transaction base (non-witness part)
        tx_base = (
            struct.pack("<L", self.tx_version) +  # Version
            b'\x00\x01' +                         # Marker and flag for SegWit
            b'\x01' +                             # Input count
            self.prev_transaction +               # Previous transaction hash
            struct.pack("<L", self.prev_output_index) +  # Previous output index
            bytes([len(script_sig)]) + script_sig +  # ScriptSig (redeem script)
            struct.pack("<L", self.sequence_number) + # Sequence
            b'\x01' +                             # Output count
            struct.pack("<Q", self.amount_sats) + # Output amount
            output_script                         # Output script (P2SH)
        )

        # Generate signatures for witness data
        msg_hash = self.hash256(self.sighash_preimage())
        signatures = self.generate_signature(msg_hash)

        # Build witness data (signatures + witness script)
        witness = (
            b'\x04' +                             # Number of witness elements (4 for 2-of-2 multisig)
            b'\x00' +                             # Dummy element for scriptSig
            bytes([len(signatures[0])]) + signatures[0] +  # First signature
            bytes([len(signatures[1])]) + signatures[1] +  # Second signature
            bytes([len(self.witness_script)]) + self.witness_script  # Witness script
        )

        # Combine all components and append locktime
        return tx_base + witness + struct.pack("<L", self.locktime)

    def save_transaction(self):
        """Write hex-encoded transaction to file"""
        with open("../out.txt", "w") as f:
            f.write(self.construct_transaction().hex())

if __name__ == "__main__":
    # Create and save transaction
    transaction = P2SH_P2WSH_Transaction()
    transaction.save_transaction()