#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h> 
#include <seccomp.h>     
#include <errno.h>
// --- CÁC MACRO LOGGING VÀ MÀU SẮC ANSI ---
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_MAGENTA "\x1b[35m"

#define LOG_INFO(msg, ...)    fprintf(stdout, COLOR_BLUE "[INFO] " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(msg, ...) fprintf(stdout, COLOR_GREEN "[SUCCESS] " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_WARN(msg, ...)    fprintf(stderr, COLOR_YELLOW "[WARN] " COLOR_RESET msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...)   fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET msg " (errno: %s)\n", ##__VA_ARGS__, strerror(errno))
extern char **environ; // Cần cho execve
int setup_seccomp(char *syscall_list, char mode){

    LOG_INFO("Bắt đầu thiết lập Seccomp filter...");
    scmp_filter_ctx ctx;

    if (mode == 'd') {
        ctx = seccomp_init(SCMP_ACT_ALLOW); // Blacklist: Mặc định cho phép
        LOG_INFO("Chế độ: BLACKLIST (Chặn các syscall cụ thể, còn lại ALLOW)");
    } else { // mode == 'e'
        ctx = seccomp_init(SCMP_ACT_KILL);  // Whitelist: Mặc định chặn (KILL)
        LOG_INFO("Chế độ: WHITELIST (Mặc định KILL, chỉ cho phép các syscall cụ thể)");
    }
    
    if(ctx == NULL){
        perror("[SECCOM INIT FAIL]");
        return -1;
    }

        //
    // seccomp_set_attribute(ctx, 
    //                     SCMP_FLT_CTL_API_EXT_FILTER_FLAGS,
    //                     SCMP_FLT_ASYNC_KILLS);
    

    char* token;
    char *syscall_names[] = {
        "open",
        "fork",
        "write",
        "read",
        "socket",
        "kill",
        "shutdown"
    };
    long syscall_nrs[] = {
        __NR_open,
        __NR_fork,
        __NR_write,
        __NR_read,
        __NR_socket,
        __NR_kill,
        __NR_shutdown
    };
    char *list_copy = strdup(syscall_list);

    if (mode == 'd') {
        LOG_INFO("Chế độ: BLACKLIST (Chặn các syscall cụ thể, còn lại ALLOW)");

        token = strtok(list_copy, ",");
        while (token != NULL){
            long sys_nr = -1;
            for (int i = 0; i < sizeof(syscall_names)/sizeof(char*); i++) {
                if(strcmp(token, syscall_names[i]) == 0) {
                    sys_nr = syscall_nrs[i];
                    break;
                }
            }

            if (sys_nr != -1) {
                // Thêm quy tắc: Chặn system call này (trả về lỗi EPERM)
                if(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), sys_nr, 0) < 0){
                    LOG_ERROR("seccomp_rule_add (deny) thất bại");
                    free(list_copy);
                    //seccomp_release(ctx);
                    return -1;
                }
                fprintf(stdout, COLOR_RED "[DENY]" COLOR_RESET "Đã chặn system call: %s\n", token);
            } else {
                LOG_WARN("System call '%s' không được hỗ trợ trong danh sách chặn", token);
            }
            token = strtok(NULL, ",");
        }
    }
    else if (mode == 'e') {
        // Chế độ WHITELIST (-e: allow/chỉ cho phép)
        LOG_INFO("Chế độ: WHITELIST (Mặc định KILL, chỉ cho phép các syscall cụ thể)");
        // Chan tat ca cac kill
        //seccomp_set_attr(ctx, SCMP_FLT_CTL_POLICY_ACTION_DEFAULT, SCMP_ACT_KILL);
       // seccomp_set_attribute(ctx, SCMP_FILTER_FLAG_SPECIFIC_ACTION, SCMP_ACT_KILL);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_exit_group, 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_brk, 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_mmap, 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_close, 0);
        fprintf(stdout, COLOR_GREEN "[ALLOW]" COLOR_RESET "Các syscall hệ thống cơ bản đã được cho phép.\n");

        token = strtok(list_copy, ",");
        while (token != NULL) {
            long sys_nr = -1;
            for (int i = 0; i < sizeof(syscall_names) / sizeof(char *); i++) {
                if (strcmp(token, syscall_names[i]) == 0) {
                    sys_nr = syscall_nrs[i];
                    break;
                }
            }
            
            if(sys_nr != -1){
                if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sys_nr, 0) < 0){
                    LOG_ERROR("seccomp_rule_add (allow) thất bại");
                    free(list_copy);
                    //seccomp_release(ctx);
                    return -1;
                }
                fprintf(stdout, COLOR_GREEN "[ALLOW] " COLOR_RESET "Đã cho phép system call: %s\n", token);

            } else {
                LOG_WARN("System call '%s' không được hỗ trợ trong danh sách cho phép", token);
            }
        token = strtok(NULL, ",");
        }
    } else {
        LOG_ERROR("Chế độ chạy không hợp lệ: %c. Chỉ chấp nhận -d hoặc -e", mode);
        free(list_copy);
        //seccomp_release(ctx);
        return -1;
    }
    // Load filter into kernel
    if(seccomp_load(ctx) < 0) {
        LOG_ERROR("seccomp_load fail");
        free(list_copy);
       // seccomp_release(ctx);
        return -1;
    }

    LOG_SUCCESS("Thiet lap Seccomp hoan tat. Bo loc da duoc ap dung");
    free(list_copy);
    //seccomp_release(ctx);
    return 0;
}

int main(int argc, char *argv[]){
    // Chương trình yêu cầu ít nhất 5 đối số: 
    // [0]=./saferun [1]=-d/-e [2]=syscall_list [3]=-- [4]=target_program
    
    // Sửa 1: Thay đổi điều kiện argc < 4 thành argc < 5
    if (argc < 5 || 
        (strcmp(argv[1], "-d") != 0 && strcmp(argv[1], "-e") != 0) || 
        (argc > 3 && strcmp(argv[3], "--") != 0)
    ) {
        
        fprintf(stderr, "\n[ERROR] Cu phap dong lenh khong hop le.\n");
        fprintf(stderr, "Cach su dung: \n");
        fprintf(stderr, "  ./saferun -d <syscall_list> <target_program> -- [args...]\n");
        fprintf(stderr, "  ./saferun -e <syscall_list> <target_program> -- [args...]\n");
        
        return 1;
    }

    char mode = argv[1][1]; // 'd' or 'e'
    char *syscall_list = argv[2];
    char *target_program = argv[4];
    char **child_argv = &argv[4];
    LOG_INFO("Saferun is starting");

    pid_t pid = fork();
    if (pid == 0) {
        // - Tien trinh con 
        LOG_INFO("Tien trinh con (PID: %d) chuan bi ap dung bo loc.", getpid());

        if(setup_seccomp(syscall_list, mode) != 0) {
            exit(1);
        }

        // Chay chuong trinh dich bang execvp
        LOG_INFO("Thuc thi chuong trinh dich: %s", target_program);
        execve(target_program, child_argv, environ);

        
        LOG_ERROR("execvp fail (check prog %s)", target_program); // Neu execvp thanh cong thi k chay den dong ay
        exit(1);
    } else {
        // - Tien trinh cha
        int status;
        LOG_INFO("Đang chờ tiến trình con (PID: %d) kết thúc...", pid);
        waitpid(pid, &status, 0);
        if(WIFEXITED(status)){
            LOG_SUCCESS("Tiến trình con kết thúc bình thường. Mã thoát: %d", WEXITSTATUS(status));
        } else if(WIFSIGNALED(status)){
            LOG_WARN("Tiến trình con bị kết thúc bởi tín hiệu: %d (%s)", WTERMSIG(status), strsignal(WTERMSIG(status)));
             // SIGSYS (31) là dấu hiệu phổ biến khi seccomp chặn bằng SCMP_ACT_KILL
            if (WTERMSIG(status) == SIGSYS) {
                 LOG_WARN("RẤT CÓ THỂ TIẾN TRÌNH ĐÃ BỊ CHẶN BỞI SECCOMP (SIGSYS)");
            }
        }
    }
    return 0;
}