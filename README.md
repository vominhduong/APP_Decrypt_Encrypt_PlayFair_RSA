# 🔐 Crypto Lab – Playfair & RSA GUI Application

## 1. Giới thiệu
Crypto Lab là một ứng dụng minh họa các giải thuật mật mã cơ bản, bao gồm **Playfair Cipher** và **RSA**, được xây dựng với giao diện đồ họa bằng **Python Tkinter**.  
Ứng dụng phục vụ mục đích **học tập, nghiên cứu và thực hành môn An toàn thông tin / Mật mã học**.

---

## 2. Các chức năng chính

### 🔹 Playfair Cipher
- Chuẩn hóa văn bản (uppercase, loại ký tự đặc biệt, gộp I/J)
- Tự động tách plaintext thành các cặp ký tự (digraph)
- Chèn ký tự đệm `X` khi cần thiết
- Mã hóa và giải mã theo đúng 3 quy tắc Playfair:
  - Cùng hàng
  - Cùng cột
  - Hình chữ nhật
- Hiển thị bảng Playfair 5×5 trực quan

### 🔹 RSA Cryptosystem
- Sinh cặp khóa RSA với độ dài 1024 hoặc 2048 bit
- Sử dụng kiểm tra nguyên tố **Miller–Rabin**
- Hỗ trợ mã hóa và giải mã RSA
- Áp dụng padding **PKCS#1 v1.5**
- Mã hóa kết quả dưới dạng **Base64**
- Giao diện rõ ràng cho public key, private key và dữ liệu xử lý

---

## 3. Công nghệ sử dụng
- **Ngôn ngữ**: Python 3
- **Giao diện**: Tkinter (ttk, scrolledtext)
- **Thư viện tiêu chuẩn**:
  - `math`, `secrets`
  - `base64`
  - `threading`

> Ứng dụng không sử dụng thư viện mật mã ngoài (như PyCrypto, cryptography) để đảm bảo tính minh họa thuật toán.

---

## 4. Luồn hoạt động (tổng quát)
<img width="784" height="432" alt="image" src="https://github.com/user-attachments/assets/fbdf1024-37ff-42f4-aa03-86a62524e579" />


