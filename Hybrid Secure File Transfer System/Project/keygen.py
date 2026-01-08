# keygen.py
from crypto_utils import generate_rsa_keypair, save_pem

if __name__ == "__main__":
    priv_pem, pub_pem = generate_rsa_keypair()
    save_pem(priv_pem, pub_pem, "receiver_private.pem", "receiver_public.pem")
    print("Generated receiver_private.pem and receiver_public.pem")
