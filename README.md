#  System Call Tracing Project (Linux - Ubuntu 22.04)

##  Giới thiệu
Project này giúp tìm hiểu **system call** trong Linux bằng cách:
- Viết một chương trình C đơn giản (`simple_target.c`) có sử dụng `printf` và `write`.
- Dùng `strace` để theo dõi các system call được gọi.
- Lọc riêng một số system call (ví dụ: `write`) và lưu kết quả ra file log.
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
   make
   sinh ra file thực thi `simple_target`.
3. Chạy chương trình:
    ```bash
   ./simple_target
    //Kết quả: Hello from simple_target!
            //Writing directly to stdout using write syscall.
4. Trace toàn bộ system call:
    ```bash
    strace -o trace.log ./simple_target
    cat trace.log
    //Trong `trace.log` bạn sẽ thấy rất nhiều system call được gọi như `execve`, `brk`, `mmap`, `write`, `exit_group`...
5. Trace riêng system call `write` và lưu vào `trace_write.log`:
    ```bash
    chmod +x trace_write.sh
    ./trace_write.sh
    cat trace_write.log
    ## Phân tích kết quả
    Trong `trace_write.log`, bạn sẽ thấy các dòng liên quan đến system call `write`, ví dụ:
        (1, "Hello from simple_target!\n", 26) → danh sách tham số:
        1 → file descriptor (FD):
        0 = stdin
        1 = stdout
        2 = stderr
        "Hello from simple_target!\n" → nội dung dữ liệu ghi ra 26 
        → số byte cần ghi = 26 → giá trị trả về (số byte thực sự đã ghi).