#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h> 
#include <sys/wait.h>

// Màu sắc cho chương trình con
#define SC_COLOR_MAGENTA "\x1b[32m"
#define SC_COLOR_RESET   "\x1b[0m"

int main(int argc, char *argv[]){
    fprintf(stderr, 
        SC_COLOR_MAGENTA "--- Chương trình Suspected đang chạy (PID: %d) ---\n" SC_COLOR_RESET, 
        getpid());

    // Kiem tra syscall fork()
    pid_t pid = fork();
    if(pid == -1){
        if(errno == EPERM){
            fprintf(stderr, 
                SC_COLOR_MAGENTA "[FAIL-BLOCKED]" 
                SC_COLOR_RESET "fork() that bai: Operation not permitted (SECCOMP DENY)\n");
        } else {
            perror("Loi khi goi fork()");
        }
    } else if(pid == 0) {
        fprintf(stdout, 
            SC_COLOR_MAGENTA"[SUCCESS]" 
            SC_COLOR_RESET "fork() thanh cong (Tien trinh con).\n");
        exit(0);
    } else {
        fprintf(stdout, 
            SC_COLOR_MAGENTA"[SUCCESS]" 
            SC_COLOR_RESET "fork() thah cong (Tien trinh cha). ID con: %d\n", pid);
        waitpid(pid, NULL, 0);
    }

    // Kiem tra system call 'open'
    int fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd == -1) {
        if (errno == EPERM){
            fprintf(stderr, 
                SC_COLOR_MAGENTA "[FAIL - BLOCK]"
                SC_COLOR_RESET "open() that bai: Operation not permitted (SECCOMP DENY)\n");
        } else {
            perror("Loi khi goi open()");
        }

    } else {
        fprintf (stdout,
        SC_COLOR_MAGENTA "[SUCCESS]" 
        SC_COLOR_RESET "open() thanh cong.\n");
        // Kiem tra write
        const char *meggage = "Du lieu da duoc ghi.\n";
        if(write(fd, meggage, 21) == -1){
            if(errno == EPERM) {
                fprintf(stderr, SC_COLOR_MAGENTA "FAIL-BLOCK"
                        SC_COLOR_RESET "write() thất bại: Operation not permitted (SECCOMP DENY)\n");
            } else {
                perror("Loi khi goi write()");
            }
        } else {
            fprintf(stdout, SC_COLOR_MAGENTA "[SUCCESS]" 
                    SC_COLOR_RESET "write() thành công.\n");
        }
        close(fd);
    }

    fprintf(stdout, SC_COLOR_MAGENTA "--- Chương trình Suspected kết thúc ---\n" SC_COLOR_RESET);
    return 0;
}