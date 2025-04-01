from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

load_dotenv()


ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

# if not ENCRYPTION_KEY:
#     ENCRYPTION_KEY = Fernet.generate_key()  # Generate if not set
#     print(f"Generated Encryption Key: {ENCRYPTION_KEY.decode()}")

cipher = Fernet(ENCRYPTION_KEY)
def encrypt_data(data: str) -> str:
    """Encrypt the given data using Fernet."""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt the given data using Fernet."""
    return cipher.decrypt(encrypted_data.encode()).decode()