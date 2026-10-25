#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline)) unsigned int linux_group(struct group *entry) {
    getgrgid_r(7, entry, 0, 0, 0);
    return entry->gr_gid;
}

__attribute__((noinline)) int linux_file(int fd) {
    return fsync(fd);
}

__attribute__((noinline)) int linux_process(int process) {
    return kill(process, 0);
}

__attribute__((noinline)) int linux_memory(void *address, size_t size) {
    return mprotect(address, size, PROT_READ);
}

__attribute__((noinline)) int linux_socket(int fd) {
    return shutdown(fd, SHUT_RD);
}

__attribute__((noinline)) int linux_thread(pthread_t thread) {
    return pthread_kill(thread, 0);
}

int main(void) {
    return 0;
}
