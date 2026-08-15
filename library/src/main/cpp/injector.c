/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <elf.h>
#include <signal.h>
#include <android/dlext.h>

#include <android/log.h>
#define LOG(fmt, ...)  __android_log_print(ANDROID_LOG_INFO, "ForgeStore", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "ForgeStore", fmt, ##__VA_ARGS__)

#if defined(__aarch64__)
#define REG_PC(r)      ((r)->pc)
#define REG_SP(r)      ((r)->sp)
#define REG_RET(r)     ((r)->regs[0])
#define REG_ARG0(r)    ((r)->regs[0])
#define REG_ARG1(r)    ((r)->regs[1])
#define REG_ARG2(r)    ((r)->regs[2])
#define REG_ARG3(r)    ((r)->regs[3])
#define REG_ARG4(r)    ((r)->regs[4])
#define REG_ARG5(r)    ((r)->regs[5])
#define REG_LR(r)      ((r)->regs[30])
#elif defined(__ARM_ARCH_7A__) || defined(__arm__)
#define REG_PC(r)      ((r)->uregs[15])
#define REG_SP(r)      ((r)->uregs[13])
#define REG_RET(r)     ((r)->uregs[0])
#define REG_ARG0(r)    ((r)->uregs[0])
#define REG_ARG1(r)    ((r)->uregs[1])
#define REG_ARG2(r)    ((r)->uregs[2])
#define REG_ARG3(r)    ((r)->uregs[3])
#define REG_ARG4(r)    ((r)->uregs[4])
#define REG_ARG5(r)    ((r)->uregs[5])
#define REG_LR(r)      ((r)->uregs[14])
#define user_regs_struct user_regs
#elif defined(__x86_64__)
#define REG_PC(r)      ((r)->rip)
#define REG_SP(r)      ((r)->rsp)
#define REG_RET(r)     ((r)->rax)
#define REG_ARG0(r)    ((r)->rdi)
#define REG_ARG1(r)    ((r)->rsi)
#define REG_ARG2(r)    ((r)->rdx)
#define REG_ARG3(r)    ((r)->rcx)
#define REG_ARG4(r)    ((r)->r8)
#define REG_ARG5(r)    ((r)->r9)
#define REG_LR(r)      ((r)->rsp)
#elif defined(__i386__)
#define REG_PC(r)      ((r)->eip)
#define REG_SP(r)      ((r)->esp)
#define REG_RET(r)     ((r)->eax)
#define REG_ARG0(r)    ((r)->ebx)
#define REG_ARG1(r)    ((r)->ecx)
#define REG_ARG2(r)    ((r)->edx)
#define REG_ARG3(r)    ((r)->esi)
#define REG_ARG4(r)    ((r)->edi)
#define REG_ARG5(r)    ((r)->esi)
#define REG_LR(r)      ((r)->esp)
#else
#error "Unsupported architecture (supported: aarch64, arm, x86_64, x86)"
#endif

static int get_regs(int pid, struct user_regs_struct *r)
{
    struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_regs(int pid, const struct user_regs_struct *r)
{
    struct iovec iov = { .iov_base = (void *)r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int wait_for_trace(int pid, int *status)
{
    while (1) {
        pid_t ret = waitpid(pid, status, __WALL);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret < 0 || !WIFSTOPPED(*status)) {
            return 0;
        }
        return 1;
    }
}

static ssize_t write_proc_mem(int pid, uintptr_t addr, const void *buf, size_t len)
{
    struct iovec lo = { .iov_base = (void *)buf, .iov_len = len };
    struct iovec ro = { .iov_base = (void *)addr, .iov_len = len };
    ssize_t r = process_vm_writev(pid, &lo, 1, &ro, 1, 0);
    if (r < 0 && errno == ENOSYS) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/mem", pid);
        int fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        r = pwrite(fd, buf, len, (off_t)addr);
        close(fd);
    }
    return r;
}

static ssize_t read_proc_mem(int pid, uintptr_t addr, void *buf, size_t len)
{
    struct iovec lo = { .iov_base = buf, .iov_len = len };
    struct iovec ro = { .iov_base = (void *)addr, .iov_len = len };
    ssize_t r = process_vm_readv(pid, &lo, 1, &ro, 1, 0);
    if (r < 0 && errno == ENOSYS) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/mem", pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        r = pread(fd, buf, len, (off_t)addr);
        close(fd);
    }
    return r;
}

static uintptr_t find_module_base(int pid, const char *suffix)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end, offset;
        char perms[8], lib[256];
        lib[0] = '\0';
        sscanf(line, "%lx-%lx %7s %lx %*s %*s %255s", &start, &end, perms, &offset, lib);
        if (offset != 0) continue;
        const char *bn = strrchr(lib, '/');
        bn = bn ? bn + 1 : lib;
        if (strcmp(bn, suffix) == 0) { fclose(f); return start; }
    }
    fclose(f);
    return 0;
}

static uintptr_t find_func_addr(int pid, const char *lib, const char *sym)
{
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) { LOG("dlopen %s failed: %s", lib, dlerror()); return 0; }
    void *s = dlsym(h, sym);
    if (!s) { LOG("dlsym %s in %s failed", sym, lib); dlclose(h); return 0; }
    uintptr_t lb = find_module_base(getpid(), lib);
    uintptr_t rb = find_module_base(pid, lib);
    dlclose(h);
    if (!lb || !rb) { LOG("base not found for %s", lib); return 0; }
    return rb + ((uintptr_t)s - lb);
}

static uintptr_t push_memory(int pid, struct user_regs_struct *regs,
                               const void *data, size_t len)
{
    REG_SP(regs) -= (len + 15) & ~15;
    REG_SP(regs) &= ~15ULL;
    uintptr_t addr = REG_SP(regs);
    if (write_proc_mem(pid, addr, data, len) < 0) return 0;
    return addr;
}

static int remote_pre_call(int pid, struct user_regs_struct *regs,
                            uintptr_t func, uintptr_t ret_addr,
                            int nargs, uintptr_t *args)
{
    if (nargs > 0) REG_ARG0(regs) = args[0];
    if (nargs > 1) REG_ARG1(regs) = args[1];
    if (nargs > 2) REG_ARG2(regs) = args[2];
    if (nargs > 3) REG_ARG3(regs) = args[3];
    if (nargs > 4) REG_ARG4(regs) = args[4];
    if (nargs > 5) REG_ARG5(regs) = args[5];
    REG_SP(regs) = (REG_SP(regs) - 128) & ~15ULL;
    REG_LR(regs) = ret_addr;
    REG_PC(regs) = func;
    if (set_regs(pid, regs) < 0) return 0;
    return ptrace(PTRACE_CONT, pid, 0, 0) >= 0;
}

static uintptr_t remote_post_call(int pid, struct user_regs_struct *regs,
                                   uintptr_t ret_addr)
{
    int status;
    if (!wait_for_trace(pid, &status)) {
        LOGE("wait_for_trace failed");
        return (uintptr_t)-1;
    }
    if (get_regs(pid, regs) < 0) return (uintptr_t)-1;
    if ((uintptr_t)REG_PC(regs) != ret_addr) {
        int sig = WIFSIGNALED(status) ? WTERMSIG(status) : WSTOPSIG(status);
        LOGE("post_call stop at %lx sig=%d", (unsigned long)(uintptr_t)REG_PC(regs), sig);
        return (uintptr_t)-1;
    }
    return REG_RET(regs);
}

static uintptr_t remote_call(int pid, struct user_regs_struct *regs,
                              uintptr_t func, uintptr_t ret_addr,
                              int nargs, uintptr_t *args)
{
    if (!remote_pre_call(pid, regs, func, ret_addr, nargs, args))
        return (uintptr_t)-1;
    return remote_post_call(pid, regs, ret_addr);
}

static void gen_rand(char *buf, int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { for (int i = 0; i < len; i++) buf[i] = 'a' + (rand() % 26); return; }
    unsigned char tmp[16];
    read(fd, tmp, 16); close(fd);
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < len && i < 32; i++) buf[i] = hex[tmp[i] & 0xf];
}

static void set_status_ok(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/data/adb/modules/forge_store/module.prop");
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    char buf[4096] = {0};
    ssize_t nr = read(fd, buf, sizeof(buf) - 1); close(fd);
    if (nr <= 0) return;
    char *line = strstr(buf, "description=");
    if (!line) return;
    char *desc = line + strlen("description=");
    if (strncmp(desc, "[OK]", 4) == 0) return;

    char *content = desc;
    if (content[0] == '[') {
        char *close = strchr(content, ']');
        if (close && close[1] == ' ') content = close + 2;
    }

    char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
    char new_d[512];
    snprintf(new_d, sizeof(new_d), "description=[OK] %s", content);
    size_t pl = line - buf, al = nl ? (buf + nr) - (nl + 1) : 0;
    char *out = malloc(pl + strlen(new_d) + al + 2);
    if (!out) return;
    memcpy(out, buf, pl); memcpy(out + pl, new_d, strlen(new_d));
    out[pl + strlen(new_d)] = '\n';
    if (al > 0) memcpy(out + pl + strlen(new_d) + 1, nl + 1, al);
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) { write(fd, out, pl + strlen(new_d) + 1 + al); close(fd); }
    free(out);
}

static int transfer_fd(int pid, const char *lib_path,
                        struct user_regs_struct *regs, uintptr_t ret_addr)
{
    int lib_fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (lib_fd < 0) { LOGE("open %s failed: %m", lib_path); return -1; }

    int local_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (local_sock < 0) { LOGE("socket failed: %m"); close(lib_fd); return -1; }

    uintptr_t sock_f = find_func_addr(pid, "libc.so", "socket");
    uintptr_t bind_f = find_func_addr(pid, "libc.so", "bind");
    uintptr_t recv_f = find_func_addr(pid, "libc.so", "recvmsg");
    uintptr_t close_f = find_func_addr(pid, "libc.so", "close");
    uintptr_t errno_f = find_func_addr(pid, "libc.so", "__errno");
    if (!sock_f || !bind_f || !recv_f || !close_f || !errno_f) {
        LOGE("resolve libc funcs failed"); close(local_sock); close(lib_fd); return -1; }

    uintptr_t a[] = {AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0};
    int remote_fd = (int)remote_call(pid, regs, sock_f, ret_addr, 3, a);
    if (remote_fd <= 0) {
        LOGE("remote socket failed"); close(local_sock); close(lib_fd); return -1; }
    LOG("remote socket fd=%d", remote_fd);

    char magic[16]; gen_rand(magic, 12);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, magic, 12);
    socklen_t addr_len = sizeof(sa_family_t) + 1 + 12;

    uintptr_t remote_addr = push_memory(pid, regs, &addr, sizeof(addr));
    if (!remote_addr) { LOGE("push addr failed"); close(local_sock); close(lib_fd); return -1; }

    uintptr_t b[] = {(uintptr_t)remote_fd, remote_addr, addr_len};
    uintptr_t br = remote_call(pid, regs, bind_f, ret_addr, 3, b);
    LOG("remote bind ret=%zu", br);
    if ((int)br < 0) {
        uintptr_t re = remote_call(pid, regs, errno_f, ret_addr, 0, NULL);
        int rerr = 0; read_proc_mem(pid, re, &rerr, sizeof(rerr));
        LOGE("remote bind failed: errno=%d", rerr);
        remote_call(pid, regs, close_f, ret_addr, 1, (uintptr_t[]){remote_fd});
        close(local_sock); close(lib_fd); return -1;
    }

    char cmsg_buf[CMSG_SPACE(sizeof(int))] = {0};
    uintptr_t remote_cmsg = push_memory(pid, regs, &cmsg_buf, sizeof(cmsg_buf));
    if (!remote_cmsg) { LOGE("push cmsg failed"); close(local_sock); close(lib_fd); return -1; }

    struct msghdr mh; memset(&mh, 0, sizeof(mh));
    mh.msg_control = (void*)remote_cmsg;
    mh.msg_controllen = sizeof(cmsg_buf);
    uintptr_t remote_mh = push_memory(pid, regs, &mh, sizeof(mh));
    if (!remote_mh) { LOGE("push mh failed"); close(local_sock); close(lib_fd); return -1; }

    uintptr_t rargs[] = {(uintptr_t)remote_fd, remote_mh, MSG_WAITALL};
    if (!remote_pre_call(pid, regs, recv_f, ret_addr, 3, rargs)) {
        LOGE("pre_call recvmsg failed"); close(local_sock); close(lib_fd); return -1; }
    LOG("remote recvmsg started fd=%d", remote_fd);
    usleep(50000);

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = &addr;
    mh.msg_namelen = addr_len;
    mh.msg_control = cmsg_buf;
    mh.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *cp = CMSG_FIRSTHDR(&mh);
    cp->cmsg_len = CMSG_LEN(sizeof(int)); cp->cmsg_level = SOL_SOCKET;
    cp->cmsg_type = SCM_RIGHTS; *(int*)CMSG_DATA(cp) = lib_fd;

    ssize_t sr = sendmsg(local_sock, &mh, 0);
    LOG("local sendmsg ret=%zd errno=%d lib_fd=%d", sr, errno, lib_fd);
    if (sr < 0) {
        LOGE("sendmsg failed: %m");
        close(local_sock); close(lib_fd);
        remote_call(pid, regs, close_f, ret_addr, 1, (uintptr_t[]){remote_fd});
        return -1;
    }

    uintptr_t rr = remote_post_call(pid, regs, ret_addr);
    LOG("remote recvmsg ret=%zu", rr);
    if (rr == (uintptr_t)-1) {
        LOGE("post_call recvmsg failed");
        close(local_sock); close(lib_fd);
        remote_call(pid, regs, close_f, ret_addr, 1, (uintptr_t[]){remote_fd});
        return -1;
    }
    if ((intptr_t)rr < 0) {
        uintptr_t re = remote_call(pid, regs, errno_f, ret_addr, 0, NULL);
        int rerr = 0; read_proc_mem(pid, re, &rerr, sizeof(rerr));
        LOGE("remote recvmsg returned %zd errno=%d", (ssize_t)(intptr_t)rr, rerr);
    }

    ssize_t rr_bytes = read_proc_mem(pid, remote_cmsg, &cmsg_buf, sizeof(cmsg_buf));
    LOG("remote cmsg read=%zd addr=%zx", rr_bytes, remote_cmsg);
    LOG("remote cmsg raw: %02x %02x %02x %02x %02x %02x %02x %02x",
        (unsigned char)cmsg_buf[0], (unsigned char)cmsg_buf[1],
        (unsigned char)cmsg_buf[2], (unsigned char)cmsg_buf[3],
        (unsigned char)cmsg_buf[4], (unsigned char)cmsg_buf[5],
        (unsigned char)cmsg_buf[6], (unsigned char)cmsg_buf[7]);
    mh.msg_control = cmsg_buf;
    mh.msg_controllen = sizeof(cmsg_buf);
    cp = CMSG_FIRSTHDR(&mh);
    if (!cp || cp->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cp->cmsg_level != SOL_SOCKET || cp->cmsg_type != SCM_RIGHTS) {
        LOGE("invalid remote cmsg len=%zu level=%d type=%d",
             cp ? cp->cmsg_len : 0,
             cp ? cp->cmsg_level : -1,
             cp ? cp->cmsg_type : -1);
        close(local_sock); close(lib_fd);
        remote_call(pid, regs, close_f, ret_addr, 1, (uintptr_t[]){remote_fd});
        return -1;
    }
    int tf = *(int*)CMSG_DATA(cp);

    close(local_sock); close(lib_fd);
    remote_call(pid, regs, close_f, ret_addr, 1, (uintptr_t[]){remote_fd});

    if (tf <= 0) { LOGE("invalid transferred fd %d", tf); return -1; }
    LOG("FD transferred: %d", tf);
    return tf;
}

static int do_inject(int pid, const char *lib_path)
{
    struct user_regs_struct backup;
    uintptr_t handle = 0;
    get_regs(pid, &backup);
    uintptr_t ret_addr = find_module_base(pid, "libc.so");
    if (!ret_addr) { goto cleanup; }

    uintptr_t a_dext = find_func_addr(pid, "libdl.so", "android_dlopen_ext");
    if (a_dext) {
        LOG("trying FD transfer");
        struct user_regs_struct regs = backup;
        int fd = transfer_fd(pid, lib_path, &regs, ret_addr);
        if (fd > 0) {
            android_dlextinfo info;
            memset(&info, 0, sizeof(info));
            info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
            info.library_fd = fd;
            uintptr_t info_addr = push_memory(pid, &regs, &info, sizeof(info));
            if (info_addr) {
                char fake[16]; gen_rand(fake, 8);
                char fd_path[32];
                snprintf(fd_path, sizeof(fd_path), "/lib%s.so", fake);
                uintptr_t path_addr = push_memory(pid, &regs, fd_path, strlen(fd_path) + 1);
                if (!path_addr) { LOG("push path failed"); goto cleanup; }
                uintptr_t args[] = {path_addr, RTLD_NOW, info_addr};
                handle = remote_call(pid, &regs, a_dext, ret_addr, 3, args);
                LOG("android_dlopen_ext returned %p", (void*)handle);

                if (handle == 0) {
                    uintptr_t dl_e = find_func_addr(pid, "libdl.so", "dlerror");
                    if (dl_e) {
                        uintptr_t err_str = remote_call(pid, &regs, dl_e, ret_addr, 0, NULL);
                        if (err_str > 0 && err_str != (uintptr_t)-1) {
                            char buf[256] = {};
                            read_proc_mem(pid, err_str, buf, sizeof(buf)-1);
                            LOG("dlerror: %s", buf);
                        }
                    }
                }

                if (handle > 0 && handle != (uintptr_t)-1) {
                    uintptr_t dlsym_f = find_func_addr(pid, "libdl.so", "dlsym");
                    if (dlsym_f) {
                        uintptr_t ename = push_memory(pid, &regs, "fm_entry", 9);
                        if (ename) {
                            uintptr_t a1[] = {handle, ename};
                            uintptr_t entry_f = remote_call(pid, &regs, dlsym_f, ret_addr, 2, a1);
                            LOG("dlsym(fm_entry) = %p", (void*)entry_f);
                            if (entry_f > 0 && entry_f != (uintptr_t)-1) {
                                uintptr_t a2[] = {handle};
                                uintptr_t result = remote_call(pid, &regs,
                                    entry_f, ret_addr, 1, a2);
                                LOG("fm_entry returned %p", (void*)result);
                            }
                        }
                    }
                }
            }
        }
    }

cleanup:
    set_regs(pid, &backup);
    return handle > 0 && handle != (uintptr_t)-1 ? 0 : -1;
}

static int inject_library(int pid, const char *lib_path)
{
    LOG("inject pid=%d", pid);

    {
        char path[256], line[1024];
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        FILE *f = fopen(path, "re");
        int found = 0;
        if (f) {
            while (fgets(line, sizeof(line), f))
                if (strstr(line, "libforgestore.so")) { found = 1; break; }
            fclose(f);
        }
        if (found) { LOG("already injected, skipping"); return 0; }
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        LOGE("PTRACE_ATTACH failed: %m");
        return -1;
    }

    int status;
    if (waitpid(pid, &status, __WALL) < 0) { ptrace(PTRACE_DETACH, pid, 0, 0); return -1; }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) { ptrace(PTRACE_DETACH, pid, 0, 0); return -1; }

    int rc = do_inject(pid, lib_path);

    ptrace(PTRACE_DETACH, pid, 0, 0);
    return rc;
}

int main(int argc, char *argv[])
{
    if (argc < 3) { LOGE("usage: injector <pid> <lib_path>"); return 1; }

    int pid = atoi(argv[1]);
    char *lib_path = argv[2];

    LOG("injector start, pid=%d lib=%s", pid, lib_path);
    if (access(lib_path, R_OK) < 0) { LOGE("lib not readable: %s", lib_path); return 1; }

    if (inject_library(pid, lib_path) != 0) {
        LOGE("injection failed");
        return 1;
    }

    LOG("injected successfully");
    set_status_ok();
    return 0;
}
