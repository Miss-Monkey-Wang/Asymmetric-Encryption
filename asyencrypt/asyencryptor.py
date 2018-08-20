from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class AsymmetricEncryption:

    @staticmethod
    def create_rsa_keys(passwd):
        key = RSA.generate(2048)
        encrypted_key = key.exportKey(passphrase=passwd, pkcs=8)
        with open('my_private_rsa_key.bin', 'wb') as f:
            f.write(encrypted_key)
        with open('my_rsa_public.pem', 'wb') as f:
            f.write(key.publickey().exportKey())

    @staticmethod
    def encrypt(filename, pub_key_name):
        data = open(filename, 'rb').read()
        count = len(data)
        length = 16
        if count < length:
            add = length - count
            data = data + (b'\0' * add)
        elif count > length:
            add = (length - (count % length))
            data = data + (b'\0' * add)
        out_file = open(filename+'_encrypted', 'wb')
        recipient_key = RSA.importKey(open(pub_key_name).read())
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        out_file.write(enc_session_key)
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0'*16)
        ciphertext = cipher_aes.encrypt(data)
        out_file.write(ciphertext)
        out_file.close()

    @staticmethod
    def decrypt(filename, private_key_file_name, passwd):
        fobj = open(filename, 'rb')
        private_key = RSA.importKey(open(private_key_file_name).read(), passphrase=passwd)
        enc_session_key, ciphertext = [fobj.read(x) for x in (256, -1)]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0'*16)
        data = cipher_aes.decrypt(ciphertext)

        data = data.rstrip(b'\0')
        wobj = open(filename+'_decrypted', 'wb')
        wobj.write(data)
        wobj.close()
