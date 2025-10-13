#  System Call Tracing Project (Linux - Ubuntu 22.04)

##  Giới thiệu
Project này giúp tìm hiểu cho phép hoặc chặn **system call** trong Linux bằng cách:
- Viết một chương trình C đơn giản (`suspected.c`) có sử dụng `fork`,`open` và 'wirte.
- Dùng seccomp để theo dõi các system call được gọi.
- Sử dụng filter để lọc các chương trình con thuộc danh sách cho phép hay từ chối chạy.
- Hiểu được mối liên hệ giữa code trong C và lời gọi system call trong nhân (kernel).

## 🛠 Chuẩn bị
- Ubuntu 22.04 (hoặc tương tự)
- Công cụ cần thiết:
  ```bash
  sudo apt update
  sudo apt install build-essential strace -y

## Hướng dẫn chạy
1. Clone project về máy:
    ```bash
    mkdir hdh
    cd hdh
    git clone 
2. Biên dịch chương trình:
    ```bash
   make saferun.c
   //sinh ra file thực thi `saferun`.
   make suspected.c
   //sinh ra file thực thi `suspected`.
3. Chạy chương trình:
    ```bash
   ./run/saferun -e read,write -- ./run/suspected test_run_d
    //Kết quả: [INFO] Saferun is starting
            // [INFO] Đang chờ tiến trình con (PID: 143757) kết thúc...
            // [INFO] Tien trinh con (PID: 143757) chuan bi ap dung bo loc.
            // [INFO] Bắt đầu thiết lập Seccomp filter...
            // [INFO] Chế độ: WHITELIST (Mặc định KILL, chỉ cho phép các syscall cụ thể)
            // [INFO] Chế độ: WHITELIST (Mặc định KILL, chỉ cho phép các syscall cụ thể)
            // [ALLOW]Các syscall hệ thống cơ bản đã được cho phép.
            // [ALLOW] Đã cho phép system call: read
            // [ALLOW] Đã cho phép system call: write
            // [SUCCESS] Thiet lap Seccomp hoan tat. Bo loc da duoc ap dung
            // [INFO] Thuc thi chuong trinh dich: ./run/suspected
            // [WARN] Tiến trình con bị kết thúc bởi tín hiệu: 31 (Bad system call)
            // [WARN] RẤT CÓ THỂ TIẾN TRÌNH ĐÃ BỊ CHẶN BỞI SECCOMP (SIGSYS)
