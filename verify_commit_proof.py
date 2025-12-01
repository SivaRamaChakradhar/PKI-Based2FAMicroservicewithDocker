import base64
import git
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load public key
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Load latest commit hash
repo = git.Repo(".")
commit_hash = repo.head.commit.hexsha

# Read Base64 signature from user
signature_b64 = input("Enter Base64 Signature: ").strip()

# Decode the signature
try:
    signature = base64.b64decode(signature_b64)
except:
    print("ERROR: Invalid Base64 format.")
    exit()

# Verify signature
try:
    public_key.verify(
        signature,
        commit_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n✅ Signature is VALID!")
    print("Commit proof verification successful.")
except Exception as e:
    print("\n❌ Signature verification FAILED!")
    print(str(e))
