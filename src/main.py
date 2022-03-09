from Crypto.Cipher import AES
import binascii
import secrets
import os

name = "Virtual Padlock"
encrypted_file_extension = ".enc"
delimiter = "|"

##Encryption Info:
block_size=1
block_quantity=16 ##AES only supports 16 (hex)bit keys

class encrypter:
    def __init__(self, file_path, decrypt_key=None):
        try: 
            if not os.path.isfile(file_path) and not os.path.isdir(file_path): exit(f"[{name}] - {file_path} is not supported.")
        except RuntimeError as err: exit(f"[{name}] - Runtime Error: {err}")
        self.path = file_path

        if decrypt_key == None: self.key = binascii.hexlify(os.urandom(16)); self.decrypt  = False
        else: self.key = bytes(decrypt_key.encode("utf-8")); self.decrypt = True
        print(f"[{name}] - Initialised")
    
    def execute(self):
        if os.path.isdir(self.path):
            self.on_all_files = False
            if input(f"[{name}] - File Is Directory, Encrypt/Decrypt all files in {self.path}? (y/n): ") == "y":
                print(f"[{name}] - Encrypting/Decrypting all files in {self.path}")
                self.on_all_files = True
            else:
                exit(f"[{name}] - No files to Encrypt/Decrypt")

        if os.path.isdir(self.path) and self.on_all_files:
            for file in os.listdir(self.path):
                if os.path.isfile(f"{self.path}/{file}"):
                    self.encrypt_decrypt(f"{self.path}/{file}")
            
        elif os.path.isfile(self.path):
            self.encrypt_decrypt(self.path)
        
        else:
            exit("File/Directory Not Detected")

        print(f"[{name}] - DO NOT LOSE: \nIMPORTANT [ KEY = {self.key} ] IMPORTANT")

    def encrypt_decrypt(self, file_path):
        file = open(file_path, "rb").read()
        ##DECRYPTING
        if self.decrypt == True: 
            print(f"[{name}] - Decrypting: {file_path}")
            if file_path.endswith(encrypted_file_extension):
                with open(f"{file_path}".removesuffix(".enc"), "wb") as f:
                    encryption_data = file.split(delimiter.encode("utf-8")) ##CipherText, Nonce, AuthTag
                    for i in range(len(encryption_data)): encryption_data[i] = binascii.unhexlify(encryption_data[i])
                    aesCipher = AES.new(self.key, AES.MODE_GCM, encryption_data[1])
                    plain_text= aesCipher.decrypt_and_verify(encryption_data[0], encryption_data[2])
                    f.write(plain_text)
            else:
                print(f"{file_path} Is Not Encrypted.")

        ##ENCRYPTING
        elif self.decrypt == False:
            print(f"[{name}] - Encrypting: {file_path}")
            aesCipher = AES.new(self.key, AES.MODE_GCM)
            ciphertext, authTag = aesCipher.encrypt_and_digest(file)
            if not file_path.endswith(encrypted_file_extension):
                with open(f"{file_path}{encrypted_file_extension}", "wb") as f:
                    f.writelines([binascii.hexlify(ciphertext), delimiter.encode("utf-8"), binascii.hexlify(aesCipher.nonce), delimiter.encode("utf-8"), binascii.hexlify(authTag)])
                print(f"[{name}] - Encryption Complete.")
            else:
                print(f"{file_path} Is Already Encrypted.")

if __name__ == "__main__":
    print(f"[{name}] - Developed by Henry Dewsnap")
    file_path = input(f"Enter File/Dir Path [FROM: {os.getcwd()}]: ")
    key = None
    if input("encrypt/decrypt [e/d]: ") == "d": key = input("Enter Decryption Key: ")
    e = encrypter(file_path, key).execute()
