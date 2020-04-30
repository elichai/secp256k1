/**********************************************************************
 * Copyright (c) 2020 Elichai Turkel	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
/*
 * In this file only the best practice randomness sources are used
 * Platform randomness sources:
 * Linux   -> `getrandom(2)`(`sys/random.h`), if not available `/dev/urandom` should be used. http://man7.org/linux/man-pages/man2/getrandom.2.html, https://linux.die.net/man/4/urandom
 * macOS   -> `getentropy(2)`(`sys/random.h`), if not available `/dev/urandom` should be used. https://www.unix.com/man-page/mojave/2/getentropy, https://opensource.apple.com/source/xnu/xnu-517.12.7/bsd/man/man4/random.4.auto.html
 * FreeBSD -> `getrandom(2)`(`sys/random.h`), if not available `kern.arandom` should be used. https://www.freebsd.org/cgi/man.cgi?query=getrandom, https://www.freebsd.org/cgi/man.cgi?query=random&sektion=4
 * OpenBSD -> `getentropy(2)`(`unistd.h`), if not available `/dev/urandom` should be used. https://man.openbsd.org/getentropy, https://man.openbsd.org/urandom
 * Windows -> `BCryptGenRandom`(`bcrypt.h`). https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
 */

#if defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif


/* Returns 1 on success, and 0 on failure. */
int fill_random(unsigned char* data, unsigned long size) {
#if defined(_WIN32)
    NTSTATUS res = BCryptGenRandom(NULL, data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (res == STATUS_SUCCESS) {
        return 1;
    } else {
        return 0;
    }
#elif defined(__linux__) || defined(__FreeBSD__)
    /* If `getrandom(2)` is not available you should fallback to /dev/urandom */
    ssize_t res = getrandom(data, size, 0);
    if (res == (ssize_t)size) {
        return 1;
    } else {
        return 0;
    }
#elif defined(__APPLE__) || defined(__OpenBSD__)
    /* If `getentropy(2)` is not available you should fallback to either `SecRandomCopyBytes` or /dev/urandom */
    int res = getentropy(data, size);
    if (res == 0) {
        return 1;
    } else {
        return 0;
    }
#endif
    return 0;
}
