import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode

# Hàm tạo OTP giả lập
def generate_otp():
    return "123456"

# Hàm tạo mã băm SHA-256
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Hàm mã hóa AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()

# Dữ liệu bệnh án
medical_data = "Họ tên: Nguyễn Văn A\nChẩn đoán: Viêm phổi cấp\nKết luận: Cần nhập viện"

# Xác thực 2FA (OTP)
print("Đang gửi OTP xác thực 2 lớp...")
otp_input = input("Nhập mã OTP được gửi (mặc định: 123456): ")
if otp_input != generate_otp():
    print("❌ Xác thực thất bại.")
    exit()

print("✅ Xác thực thành công.")

# Mã hóa và tính mã băm
key = b"1234567890abcdef"  # 16-byte AES key
encrypted = encrypt_data(medical_data, key)
hash_value = sha256_hash(medical_data)

# Gửi qua socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))
client.sendall(encrypted.encode() + b"<END>" + hash_value.encode())
client.close()

print("✅ Đã gửi bệnh án mã hóa thành công.")
