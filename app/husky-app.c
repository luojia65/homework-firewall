#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/rtc.h>
#include <linux/ioctl.h>

void main() {
    int fd = open("/dev/husky", O_RDWR);
    if (fd == -1) {
        perror("husky app: failed to open firewall device");
        exit(-1);
    }
}
