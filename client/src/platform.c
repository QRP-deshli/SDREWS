// Client                         //
// Small Windows/Linux helpers    //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#include <stdio.h>
#include <string.h>
#include "platform.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <windows.h>
  #include <io.h>
  #include <conio.h>
  /* RtlGenRandom, exported by advapi32 under this name (no extra headers needed). */
  BOOLEAN WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
#else
  #include <errno.h>
  #include <fcntl.h>
  #include <termios.h>
  #include <time.h>
  #include <unistd.h>
#endif

void plat_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
#endif
}

int plat_random(void *buf, size_t n)
{
#ifdef _WIN32
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ULONG chunk = (n > 65536U) ? 65536U : (ULONG)n;
        if (!SystemFunction036(p, chunk)) {
            return -1;
        }
        p += chunk;
        n -= chunk;
    }
    return 0;
#else
    uint8_t *p = (uint8_t *)buf;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            close(fd);
            return -1;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    close(fd);
    return 0;
#endif
}

void plat_wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) {
        *q++ = 0;
    }
}

int plat_read_secret(const char *prompt, char *buf, size_t size)
{
    size_t len = 0;

    if (size < 2) {
        return -1;
    }
    fputs(prompt, stderr);
    fflush(stderr);

#ifdef _WIN32
    if (_isatty(_fileno(stdin))) {
        for (;;) {
            int c = _getch();
            if (c == '\r' || c == '\n') {
                break;
            }
            if (c == 3) {                      /* Ctrl+C */
                plat_wipe(buf, size);
                fputc('\n', stderr);
                return -1;
            }
            if (c == '\b') {
                if (len > 0) {
                    buf[--len] = '\0';
                }
                continue;
            }
            if (c == 0 || c == 0xE0) {         /* function / arrow key: skip 2nd code */
                (void)_getch();
                continue;
            }
            if (len + 1 < size) {
                buf[len++] = (char)c;
            }
        }
        buf[len] = '\0';
        fputc('\n', stderr);
        return (int)len;
    }
#else
    if (isatty(STDIN_FILENO)) {
        struct termios oldt, newt;
        int c;
        if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
            newt = oldt;
            newt.c_lflag &= (tcflag_t)~(ECHO);
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
            while ((c = getchar()) != '\n' && c != EOF) {
                if (len + 1 < size) {
                    buf[len++] = (char)c;
                }
            }
            buf[len] = '\0';
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
            fputc('\n', stderr);
            return (c == EOF && len == 0) ? -1 : (int)len;
        }
    }
#endif
    /* Not a terminal (pipe / redirect): plain line read. */
    if (fgets(buf, (int)size, stdin) == NULL) {
        return -1;
    }
    len = strcspn(buf, "\r\n");
    buf[len] = '\0';
    return (int)len;
}
