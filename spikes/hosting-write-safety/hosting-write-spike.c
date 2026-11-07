#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void make_path(char *buffer, size_t size, const char *root, const char *name) {
    int written = snprintf(buffer, size, "%s/%s", root, name);
    require(written > 0 && (size_t)written < size, "path buffer overflow");
}

static void write_file(const char *path, const char *contents) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) fail("open fixture");
    size_t length = strlen(contents);
    ssize_t written = write(fd, contents, length);
    if (written != (ssize_t)length) fail("write fixture");
    if (close(fd) < 0) fail("close fixture");
}

static int read_file(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("open file for verification");
    ssize_t length = read(fd, buffer, size - 1);
    if (length < 0) fail("read file for verification");
    buffer[length] = '\0';
    if (close(fd) < 0) fail("close verified file");
    return (int)length;
}

static int open_beneath_without_symlinks(int root_fd, const char *relative_path) {
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    return (int)syscall(SYS_openat2, root_fd, relative_path, &how, sizeof(how));
}

static void test_openat2(const char *root, int root_fd) {
    char file_path[512];
    char outside_path[512];
    char symlink_path[512];
    make_path(file_path, sizeof(file_path), root, "index.php");
    make_path(outside_path, sizeof(outside_path), root, "../outside.txt");
    make_path(symlink_path, sizeof(symlink_path), root, "escape");

    write_file(file_path, "inside-site");
    write_file(outside_path, "outside-site");
    require(symlink(outside_path, symlink_path) == 0, "create symlink fixture");

    int valid_fd = open_beneath_without_symlinks(root_fd, "index.php");
    if (valid_fd < 0) {
        if (errno == ENOSYS || errno == EINVAL) {
            fprintf(stderr, "FAIL: openat2 resolution constraints are unavailable; refusing fallback\n");
            exit(77);
        }
        fail("openat2 valid in-root file");
    }
    close(valid_fd);
    printf("PASS: openat2 opened a regular in-root file\n");

    errno = 0;
    int traversal_fd = open_beneath_without_symlinks(root_fd, "../outside.txt");
    require(traversal_fd < 0, "openat2 must reject traversal outside the held root");
    printf("PASS: openat2 rejected parent traversal (%s)\n", strerror(errno));

    errno = 0;
    int symlink_fd = open_beneath_without_symlinks(root_fd, "escape");
    require(symlink_fd < 0, "openat2 must reject a symlink target");
    printf("PASS: openat2 rejected a symlink (%s)\n", strerror(errno));
}

static void test_unconditional_replace(const char *root) {
    char target[512];
    char staged[512];
    char user_update[512];
    char candidate[512];
    char content[64];
    make_path(target, sizeof(target), root, "race-target.txt");
    make_path(staged, sizeof(staged), root, "approved.tmp");
    make_path(user_update, sizeof(user_update), root, "user.tmp");
    make_path(candidate, sizeof(candidate), root, "noreplace.tmp");

    write_file(target, "before");
    int old_target_fd = open(target, O_RDONLY | O_CLOEXEC);
    if (old_target_fd < 0) fail("open existing target");
    if (flock(old_target_fd, LOCK_EX) < 0) fail("lock existing target");

    int length = read_file(target, content, sizeof(content));
    require(length == 6 && strcmp(content, "before") == 0, "read expected pre-change bytes");
    write_file(staged, "approved");

    pid_t writer = fork();
    if (writer < 0) fail("fork competing writer");
    if (writer == 0) {
        write_file(user_update, "user-change");
        if (rename(user_update, target) < 0) _exit(2);
        _exit(0);
    }
    int child_status = 0;
    if (waitpid(writer, &child_status, 0) < 0) fail("wait for competing writer");
    require(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0, "competing writer atomically replaces target");

    length = read_file(target, content, sizeof(content));
    require(length == 11 && strcmp(content, "user-change") == 0, "competing change exists before approved rename");
    require(rename(staged, target) == 0, "approved rename replaces target");
    length = read_file(target, content, sizeof(content));
    require(length == 8 && strcmp(content, "approved") == 0, "approved rename overwrites the competing change");
    printf("CONFIRMED: a non-cooperating writer changed the target after validation; rename overwrote it even while flock held the old inode\n");

    write_file(candidate, "new-file");
    errno = 0;
    int no_replace_result = (int)syscall(
        SYS_renameat2,
        AT_FDCWD, candidate,
        AT_FDCWD, target,
        RENAME_NOREPLACE
    );
    require(no_replace_result < 0 && errno == EEXIST, "RENAME_NOREPLACE must refuse an existing destination");
    printf("CONFIRMED: RENAME_NOREPLACE refuses an existing target; it is not conditional replacement\n");

    if (flock(old_target_fd, LOCK_UN) < 0) fail("unlock old target");
    if (close(old_target_fd) < 0) fail("close old target");
}

int main(void) {
    char temporary_root[] = "/tmp/hosting-write-spike-XXXXXX";
    char site_root[512];
    struct utsname kernel;
    if (!mkdtemp(temporary_root)) fail("create isolated temporary directory");
    make_path(site_root, sizeof(site_root), temporary_root, "site");
    if (mkdir(site_root, 0700) < 0) fail("create isolated site root");

    int root_fd = open(site_root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) fail("open trusted root directory handle");
    if (uname(&kernel) < 0) fail("read kernel version");
    printf("Linux feasibility probe on %s %s (%s)\n", kernel.sysname, kernel.release, kernel.machine);

    test_openat2(site_root, root_fd);
    test_unconditional_replace(site_root);
    close(root_fd);
    printf("RESULT: safe path resolution is feasible on this kernel; generic conditional replacement against non-cooperating writers is not established\n");
    return EXIT_SUCCESS;
}
