#if defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#include <fcntl.h>
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

#include <string.h>

/* Returns 1 on sucess, and 0 on failure. */
int fill_random(unsigned char* data, unsigned long size) {
#if defined(_WIN32)
    NTSTATUS res = BCryptGenRandom(NULL, data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (res == STATUS_SUCCESS) {
        return 1;
    } else {
        return 0;
    }
#elif defined(__linux__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    ssize_t res;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return 0;
    }
    res = read(fd, data, size);
    close(fd);
    if (res == (ssize_t)size) {
        return 1;
    } else {
        return 0;
    }
#endif
    return 0;
}

/* Cleanses memory to prevent leaking sensitive info. Won't be optimized out. */
void memclear(void *ptr, size_t len) {
#if defined(_WIN32)
    /* SecureZeroMemory is guaranteed not to be optimized out by MSVC. */
    SecureZeroMemory(ptr, n);
#elif defined(__GNUC__)
    /* We use a memory barrier that scares the compiler away from optimizing out the memset.
     *
     * Quoting Adam Langley <agl@google.com> in commit ad1907fe73334d6c696c8539646c21b11178f20f
     * in BoringSSL (ISC License):
     *    As best as we can tell, this is sufficient to break any optimisations that
     *    might try to eliminate "superfluous" memsets.
     * This method used in memzero_explicit() the Linux kernel, too. Its advantage is that it is
     * pretty efficient, because the compiler can still implement the memset() efficently,
     * just not remove it entirely. See "Dead Store Elimination (Still) Considered Harmful" by
     * Yang et al. (USENIX Security 2017) for more background.
     */
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    void *(*volatile const volatile_memset)(void *, int, size_t) = memset;
    volatile_memset(ptr, 0, len);
#endif
}
