#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static int denied_getfd(int pidfd, int fd) {
    errno = 0;
    return syscall(SYS_pidfd_getfd, pidfd, fd, 0) == -1 && errno == EPERM;
}

int main(void) {
    // Inspect inherited descriptors before this program opens any file. The
    // static C runtime startup has completed; this probe creates no descriptors.
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_max > 1048576)
        return 10;
    for (int fd = 0; fd < 3; ++fd)
        if (fcntl(fd, F_GETFD) == -1) return 11;
    for (rlim_t fd = 3; fd < limit.rlim_max; ++fd) {
        errno = 0;
        if (fcntl((int)fd, F_GETFD) != -1 || errno != EBADF) return 12;
    }

    int pidfd = (int)syscall(SYS_pidfd_open, 1, 0);
    if (pidfd < 0) return 13;
    for (int fd = 0; fd < 4; ++fd)
        if (!denied_getfd(pidfd, fd)) return 14;
    errno = 0;
    if (ptrace(PTRACE_SEIZE, 1, NULL, NULL) != -1 || errno != EPERM) return 15;

    DIR *directory = opendir("/proc/1/fd");
    if (directory == NULL) {
        if (errno != EACCES && errno != EPERM) return 16;
        // Listing denial alone is insufficient: search permission could still
        // allow a known descriptor pathname. Probe the full inherited hard
        // limit, including descriptors beyond the conventional control fd 3.
        for (rlim_t fd = 0; fd < limit.rlim_max; ++fd) {
            char path[64], target[4096];
            int length = snprintf(path, sizeof(path), "/proc/1/fd/%lu", (unsigned long)fd);
            if (length < 0 || (size_t)length >= sizeof(path)) return 25;
            errno = 0;
            if (readlink(path, target, sizeof(target)) != -1
                || (errno != EACCES && errno != EPERM && errno != ENOENT)) return 26;
            errno = 0;
            if (open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC) != -1
                || (errno != EACCES && errno != EPERM && errno != ENOENT)) return 27;
        }
    } else {
        struct dirent *entry;
        unsigned count = 0;
        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (++count > 1048576) return 17;
            char *end;
            errno = 0;
            long number = strtol(entry->d_name, &end, 10);
            if (errno || *end || number < 0 || number > INT_MAX) return 18;
            if (!denied_getfd(pidfd, (int)number)) return 19;
            char target[4096];
            errno = 0;
            if (readlinkat(dirfd(directory), entry->d_name, target, sizeof(target)) != -1
                || (errno != EACCES && errno != EPERM)) return 20;
            errno = 0;
            int obtained = openat(dirfd(directory), entry->d_name, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (obtained != -1 || (errno != EACCES && errno != EPERM)) return 21;
            errno = 0;
        }
        if (errno || count == 0) return 22;
        if (closedir(directory) != 0) return 23;
    }
    return close(pidfd) == 0 ? 0 : 24;
}
