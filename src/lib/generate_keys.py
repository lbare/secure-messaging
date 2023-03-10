import pyDH

def generate_new_DH():
    """
    Returns a new DH object with the following useful methods:
        - gen_public_key() to get the public key
        - get_private_key() to get the private key
    """
    return pyDH.DiffieHellman()

def generate_shared_key(dh_object_1, other_public_key):
    """
    Returns a shared key from two DH objects.

    Parameters:
        dh_object_1: DiffieHellman - a DH object
        other_public_key: the other public key
    """
    return dh_object_1.gen_shared_key(other_public_key)[:32]

if __name__ == "__main__":
    alice = generate_new_DH()
    bob = generate_new_DH()
    shared = generate_shared_key(alice, bob.gen_public_key())

    print(f"Alice: {alice.gen_public_key()}\n")
    print(f"Bob: {bob.gen_public_key()}\n")
    print(f"Shared key: {shared}\n")