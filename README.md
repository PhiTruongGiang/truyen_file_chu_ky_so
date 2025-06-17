1. 🔐 Đăng ký
Giao diện: Đăng ký
![Ảnh chụp màn hình 2025-06-18 015450](https://github.com/user-attachments/assets/1cfeccde-3d54-471c-b085-a16b65dbd15a)


Người dùng tạo tài khoản mới bằng tên đăng nhập và mật khẩu.

Khi đăng ký thành công, hệ thống tự động tạo cặp khóa riêng và khóa công khai RSA cho người dùng.

Các khóa này được dùng để ký và xác minh dữ liệu sau này.

2. 🔑 Đăng nhập
Giao diện: Đăng nhập
![Ảnh chụp màn hình 2025-06-18 014832](https://github.com/user-attachments/assets/48871183-c5b1-430d-abdc-25e7a1dd1faf)

Người dùng nhập tên tài khoản và mật khẩu để vào hệ thống.

Sau khi đăng nhập, người dùng sẽ được đưa đến trang chính để gửi/nhận tin nhắn và tệp.

3. 📤 Gửi tin nhắn và file
Giao diện: Dashboard
![Ảnh chụp màn hình 2025-06-18 013701](https://github.com/user-attachments/assets/1fcf421b-a22a-4118-bc16-7e6780de7d0a)

Cho phép:

Chọn người nhận.

Nhập nội dung tin nhắn.

Đính kèm tệp tin (file bất kỳ).

Khi gửi:

Tệp tin được ký điện tử bằng khóa riêng của người gửi.

Thông tin chữ ký được lưu lại kèm theo tệp và tin nhắn.

4. 📥 Hộp thư đến
Giao diện: Hộp thư đến
![Ảnh chụp màn hình 2025-06-18 015439](https://github.com/user-attachments/assets/e9a6ba45-824a-4aed-9fd3-57f03a4ee4ac)

Người dùng có thể xem:

Danh sách tin nhắn nhận được từ người khác.

Tải xuống tệp đính kèm.

Quan trọng: Hệ thống sẽ tự động xác minh chữ ký số của các tệp nhận được để đảm bảo tính toàn vẹn và xác thực:

✅ Nếu chữ ký hợp lệ: Tin nhắn hiển thị là “Đã xác thực”.

❌ Nếu chữ ký không hợp lệ hoặc bị chỉnh sửa: Cảnh báo “Không hợp lệ”.

5. 📎 Tải file đính kèm
Bất kỳ tệp nào được gửi kèm đều có thể được tải về từ giao diện Hộp thư đến.

File được bảo quản trong thư mục uploads trên server.

6. 🚪 Đăng xuất
Giao diện: Dashboard

Người dùng có thể đăng xuất để kết thúc phiên làm việc, đảm bảo bảo mật cá nhân.

✅ Tính năng bảo mật nổi bật
Sử dụng chữ ký số RSA 2048-bit để bảo vệ nội dung file.

Kiểm tra tính toàn vẹn file sau khi tải về.

Hệ thống không lưu mật khẩu dưới dạng thô trong tương lai (nên mã hóa bằng hash – gợi ý: bcrypt).
