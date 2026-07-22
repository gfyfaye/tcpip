#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int main() {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return 1;
    }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, "tap0", IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return 1;
    }

    std::printf("Opened TAP device: %s\n", ifr.ifr_name);
    std::printf("Waiting for frames... (bring the interface up in another shell)\n\n");

    uint8_t buf[2048];
    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            perror("read");
            break;
        }

        std::printf("--- frame, %zd bytes ---\n", n);
        for (ssize_t i = 0; i < n; ++i) {
            std::printf("%02x ", buf[i]);
            if (i % 16 == 15) std::printf("\n");
        }
        std::printf("\n\n");
    }

    close(fd);
    return 0;
}