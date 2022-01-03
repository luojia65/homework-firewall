#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>    
#include <sys/ioctl.h>
#include <string.h>

const unsigned int HUSKY_CMD_GET_VERS = 1;
const unsigned int HUSKY_CMD_LIST_RULES = 2;
const unsigned int HUSKY_CMD_ALLOW = 3;
const unsigned int HUSKY_CMD_DENY = 4;

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
        if((strcmp("h",buf[0])==0)||strcmp("help",buf[0])==0) {
            printf("Available commands:\n");
            printf("list: print all available firewall rules\n");
            printf("allow <cidr> <proto>: sets an allow firewall rule\n");
            printf("deny <cidr> <proto>: sets a deny firewall rule\n");
            printf("version: get firewall kernel module version\n");
            printf("exit: exit program\n");
        } else if((strcmp("v",buf[0])==0)||strcmp("ver",buf[0])==0||strcmp("version",buf[0])==0) {
            long ans = ioctl(fd,HUSKY_CMD_GET_VERS,0);
            if(ans<0) {
                perror("failed to get version\n");
            } else {
                printf("Husky version %ld.%ld\n", (ans>>8), ans&0xff);
            }
        }else if((strcmp("l",buf[0])==0)||strcmp("list",buf[0])==0) {
            // inet_addr
            long ans = ioctl(fd,HUSKY_CMD_LIST_RULES,0);
            if(ans<0) {
                perror("failed to deny rule\n");
            } else {
                perror("succeeded to deny rule\n");
            }
        }else if((strcmp("d",buf[0])==0)||strcmp("deny",buf[0])==0) {
            // inet_addr
            long ans = ioctl(fd,HUSKY_CMD_DENY,0);
            if(ans<0) {
                perror("failed to deny rule\n");
            } else {
                perror("succeeded to deny rule\n");
            }
        } else if((strcmp("a",buf[0])==0)||strcmp("allow",buf[0])==0) {
            // inet_addr
            long ans = ioctl(fd,HUSKY_CMD_ALLOW,0);
            if(ans<0) {
                perror("failed to allow rule\n");
            } else {
                perror("succeeded to allow rule\n");
            }
        } else if((strcmp("q",buf[0])==0)||strcmp("exit",buf[0])==0) {
            printf("Bye!\n");
            cmd=-1;
        } else {
            if (buf[0][0] != '\0') {
                printf("Cannot parse %s as a valid command; check your spell and try again.\n", buf[0]);
            }
        } 
    }
}
