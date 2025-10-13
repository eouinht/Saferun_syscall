#  System Call Tracing Project (Linux - Ubuntu 22.04)

##  Giới thiệu
Project này giúp tìm hiểu cho phép hoặc chặn **system call** trong Linux bằng cách:
- Viết một chương trình C đơn giản (`suspected.c`) có sử dụng `fork`,`open` và 'wirte.
- Seccomp cho phép lọc system call ở mức kernel.
- Hiểu được mối liên hệ giữa code trong C và lời gọi system call trong nhân (kernel).
## Yêu cầu:
- Thực thi một chương trình con (suspected) với các tham số chỉ định.
- Giới hạn một số system call nhất định (ví dụ: open, fork, socket, kill, shutdown, …).
- Cho phép chỉ chạy các system call an toàn, hoặc chặn những system call nguy hiểm.
- VD: Chạy chương trình suspected với các đối số a b c, nhưng không cho phép system call open và fork.
- "saferun -d:open,fork suspected -- a b c"

## 🛠 Chuẩn bị
- Ubuntu 22.04 (hoặc tương tự)
- Công cụ cần thiết:
  ```bash
  sudo apt update
  sudo apt install libseccomp-dev


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
