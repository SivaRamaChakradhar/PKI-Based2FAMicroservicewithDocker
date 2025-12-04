import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_message(message, private_key):
    return private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def encrypt_with_public_key(data, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    commit_hash = input("Enter your commit hash: ").strip()

    student_private = load_private_key("../student_private.pem")
    instructor_public = load_public_key("../instructor_public.pem")

    signature = sign_message(commit_hash, student_private)
    encrypted_sig = encrypt_with_public_key(signature, instructor_public)

    encoded = base64.b64encode(encrypted_sig).decode()
    print("\n=== COPY THIS OUTPUT FOR SUBMISSION ===\n")
    print(encoded)
    print("\n=======================================\n")

if __name__ == "__main__":
    main()
