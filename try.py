import os
import pkcs11

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='DEMO')

data = b'INPUT DATA'

# Open a session on our token
with token.open(user_pin='12345678') as session:
    # Generate an AES key in this session
    key = session.generate_key(pkcs11.KeyType.AES, 256)

    # Get an initialisation vector
    iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
    # Encrypt our data
    crypttext = key.encrypt(data, mechanism_param=iv)