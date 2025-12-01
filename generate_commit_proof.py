import git
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_pub = serialization.load_pem_public_key(f.read())

# Get latest commit hash
repo = git.Repo(".")
commit_hash = repo.head.commit.hexsha
print("Commit Hash:", commit_hash)

# Sign commit hash
signature = private_key.sign(
    commit_hash.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Encrypt signature with instructor public key
encrypted_signature = instructor_pub.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Base64 encode
b64_signature = base64.b64encode(encrypted_signature).decode("utf-8")
print("Base64 Encrypted Signature:")
print(b64_signature)
