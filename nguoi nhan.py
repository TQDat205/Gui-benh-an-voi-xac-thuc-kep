import socket
import hashlib
from Crypto.Cipher import AES
from base64 import b64decode

# Hàm xác thực OTP
def verify_otp():
    otp = input("Nhập mã OTP nhận được: ")
    return otp == "123456"

# Hàm giải mã AES
def decrypt_data(encrypted_b64, key):
    encrypted = b64decode(encrypted_b64)
    nonce = encrypted[:16]
    tag = encrypted[16:32]
    ciphertext = encrypted[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Hàm kiểm tra toàn vẹn SHA-256
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Mở cổng TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen(1)

print("🟢 Đang chờ người gửi kết nối...")

conn, addr = server.accept()
print(f"📥 Đã kết nối từ {addr}")

data = conn.recv(4096)
conn.close()

# Tách mã hóa và hash
encrypted_b64, hash_received = data.decode().split("<END>")

# Yêu cầu xác thực 2FA
if not verify_otp():
    print("❌ Xác thực thất bại. Từ chối giải mã.")
    exit()

print("✅ Xác thực thành công. Đang giải mã...")

# Giải mã
key = b"1234567890abcdef"
try:
    decrypted = decrypt_data(encrypted_b64, key)
    print("🔓 Dữ liệu sau giải mã:")
    print(decrypted)

    # Kiểm tra hash
    hash_calculated = sha256_hash(decrypted)
    if hash_calculated == hash_received:
        print("✅ Toàn vẹn dữ liệu xác nhận.")
    else:
        print("⚠️ Cảnh báo: Dữ liệu có thể đã bị thay đổi!")

except Exception as e:
    print("❌ Giải mã thất bại:", e)
