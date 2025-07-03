import hashlib
import random
import smtplib
from email.message import EmailMessage
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ======== Tạo mã OTP ==========
def generate_otp():
    return str(random.randint(100000, 999999))

# ======== Gửi mã OTP qua email (giả lập) ==========
def send_otp(email, otp):
    print(f"[GIẢ LẬP] Gửi mã OTP {otp} đến email: {email}")
    # Thực tế có thể dùng smtplib để gửi thật

# ======== Hàm mã hóa AES ==========
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, ciphertext, tag

# ======== Hàm băm SHA-256 ==========
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ======== Giao diện chính ==========
def main():
    # Bước 1: Nhập dữ liệu bệnh án
    medical_record = input("Nhập thông tin bệnh án: ")

    # Bước 2: Xác thực OTP
    email = input("Nhập email người gửi: ")
    otp = generate_otp()
    send_otp(email, otp)

    entered_otp = input("Nhập mã OTP đã nhận: ")
    if entered_otp != otp:
        print("❌ Xác thực thất bại. Dừng hệ thống.")
        return

    print("✅ Xác thực thành công!")

    # Bước 3: Mã hóa bệnh án
    key = get_random_bytes(16)  # AES-128
    nonce, ciphertext, tag = encrypt_data(medical_record, key)

    # Bước 4: Băm để kiểm tra toàn vẹn
    hash_value = hash_data(medical_record)

    # Giả lập gửi dữ liệu
    print("\n🎯 Gửi dữ liệu đến máy chủ:")
    print(f"- Dữ liệu mã hóa: {ciphertext.hex()}")
    print(f"- Nonce: {nonce.hex()}")
    print(f"- Tag: {tag.hex()}")
    print(f"- Mã băm SHA-256: {hash_value}")
    print(f"- Khóa AES (phải truyền an toàn): {key.hex()}")

if __name__ == "__main__":
    main()
