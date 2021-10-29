#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/rtc.h>
#include <linux/ioctl.h>
#include <string.h>

char buf[20][1005];

void main() {
    int fd = open("/dev/husky", O_RDWR);
    if (fd == -1) {
        perror("husky app: failed to open firewall device");
        exit(-1);
    }
    printf("Welcome to husky firewall manager application!\n");
    printf("Use command 'help' to get a list of command you may use.\n");
    int cmd=0;
    while(cmd!=-1) {
        printf("> ");
        char c; int n=0, j=0;
        while(c=getchar(), c==' ');
        do {
            if(c==' ') {
                buf[n][j]='\0';
                n++, j=0;
            } else if(c=='\r' ||c=='\n') {
                buf[n][j]='\0';
                n++;
                break;
            } else {
                buf[n][j++]=c;
            }
        } while(c=getchar(), c!=EOF);
        // for(int i=0;i<n;++i) {
        //     printf("cmd[%d]=%s\n",i,buf[i]);
        // }
        if((strcmp("q",buf[0])==0)||strcmp("exit",buf[0])==0) {
            printf("Bye!\n");
            cmd=-1;
        } else {
            if (buf[0][0] != '\0') {
                printf("Cannot parse %s as a valid command; check your spell and try again.\n", buf[0]);
            }
        } 
    }
}
