#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/errno.h>
#include <asm/uaccess.h>
#include <stdbool.h>

struct husky_firewall_rule {
    struct husky_firewall_rule *next;
    __be32 src_addr; // 0代表所有地址
    __be32 src_mask; // 掩码
    __be32 dst_addr;
    __be32 dst_mask; // 掩码
    __be16 src_port; // 0代表所有端口
    __be16 dst_port;
    int flags;
};

const int HUSKY_DENY_TCP = 1;
const int HUSKY_DENY_UDP = 2;

static struct husky_firewall_rule *firewall_rules;

unsigned int pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_ICMP) {
        return NF_ACCEPT;
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        struct husky_firewall_rule *cur = firewall_rules;
        while (cur != NULL) {
            // printk(KERN_INFO
            //         "TCP packet %pI4:%u to %pI4:%u, seq %u, ackseq %u, Rule: (%d)%d %d %d %d %d\n", 
            //         &iph->saddr, ntohs(tcph->source),
            //         &iph->daddr, ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq),
            //     cur->flags, (cur->flags & HUSKY_DENY_TCP) ,
            //     (ntohl(iph->daddr) & ntohl(cur->dst_mask)) == ntohl(cur->dst_addr),
            //     (ntohl(iph->saddr) & ntohl(cur->src_mask)) == ntohl(cur->src_addr),
            //     (cur->dst_port == 0 || ntohs(tcph->dest) == cur->dst_port),
            //     (cur->src_port == 0 || ntohs(tcph->source) == cur->src_port)
            // );
            if (
                (cur->flags & HUSKY_DENY_TCP) &&
                (ntohl(iph->daddr) & ntohl(cur->dst_mask)) == cur->dst_addr &&
                (ntohl(iph->saddr) & ntohl(cur->src_mask)) == cur->src_addr &&
                (cur->dst_port == 0 || ntohs(tcph->dest) == cur->dst_port) &&
                (cur->src_port == 0 || ntohs(tcph->source) == cur->src_port)
            ) {
                printk(KERN_INFO
                    "Dropped tcp packet %pI4:%u to %pI4:%u\n",
                    &iph->saddr, ntohs(tcph->source),
                    &iph->daddr, ntohs(tcph->dest)
                );
                return NF_DROP;
            }
            cur = cur->next;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = udp_hdr(skb);
        struct husky_firewall_rule *cur = firewall_rules;
        while (cur != NULL) {
            if (
                (cur->flags & HUSKY_DENY_UDP) &&
                (ntohl(iph->daddr) & ntohl(cur->dst_mask)) == cur->dst_addr &&
                (ntohl(iph->saddr) & ntohl(cur->src_mask)) == cur->src_addr &&
                (cur->dst_port == 0 || ntohs(udph->dest) == cur->dst_port) &&
                (cur->src_port == 0 || ntohs(udph->source) == cur->src_port)
            ) {
                printk(KERN_INFO
                    "Dropped udp packet %pI4:%u to %pI4:%u\n",
                    &iph->saddr, ntohs(udph->source),
                    &iph->daddr, ntohs(udph->dest)
                );
                return NF_DROP;
            }
            cur = cur->next;
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops pre_routing_ops = {
    .hook = pre_routing_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

void insert_rule(
    __be32 src_addr, __be32 src_mask, __be16 src_port, 
    __be32 dst_addr, __be32 dst_mask, __be16 dst_port, 
    int flags
) {
    struct husky_firewall_rule *new_rule = (struct husky_firewall_rule*)
        kmalloc(sizeof(struct husky_firewall_rule), GFP_KERNEL);
    new_rule->src_addr = src_addr;
    new_rule->src_mask = src_mask;
    new_rule->src_port = src_port;
    new_rule->dst_addr = dst_addr;
    new_rule->dst_mask = dst_mask;
    new_rule->dst_port = dst_port;
    new_rule->flags = flags;
    new_rule->next = firewall_rules;
    firewall_rules = new_rule;
}

static struct cdev husky_cdev;
  
int husky_open(struct inode *inode, struct file *file) {
    try_module_get(husky_cdev.owner);
    return 0;
}

int husky_release(struct inode *inode, struct file *file) {
    module_put(husky_cdev.owner);
    return 0;
}

const unsigned int HUSKY_CMD_GET_VERS = 1;
const unsigned int HUSKY_CMD_LIST_RULES = 2;
const unsigned int HUSKY_CMD_ALLOW = 3;

long husky_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case HUSKY_CMD_GET_VERS:
            return 0x100;
        case HUSKY_CMD_LIST_RULES:

            return 0;
    }
    return -EBADRQC;
}

struct file_operations husky_fops = {
    .unlocked_ioctl = husky_ioctl,
    .open = husky_open,
    .release = husky_release,
};

#define HUSKY_MAJOR 100

// 使用之前：sudo mknod /dev/husky c 100 0

static int __init mod_init(void) {
    int retval;
    dev_t dev = 0;
    dev = MKDEV(HUSKY_MAJOR, 0); 
    retval = register_chrdev_region(dev, 1, "husky");
    if (retval) return retval;
 
    cdev_init(&husky_cdev, &husky_fops);
    retval = cdev_add(&husky_cdev, dev, 1);
    if (retval) return retval;
    
    printk(KERN_NOTICE "husky: registering char device %d.%d\n", MAJOR(dev), MINOR(dev));
    firewall_rules = NULL;
    insert_rule(0, 0, 0, 0, 0, 8000, HUSKY_DENY_TCP);
    // 有很多个网络命名空间，这里选择初始启动时的空间init_net
    // 也就意味着husky暂时不支持多个命名空间的情况
    nf_register_net_hook(&init_net, &pre_routing_ops);
    printk(KERN_NOTICE "husky: firewall service (kernel module) has successfully started\n");
    return 0;
}

static void __exit mod_exit(void) {
    dev_t devno;
    nf_unregister_net_hook(&init_net, &pre_routing_ops);
    devno = MKDEV(HUSKY_MAJOR, 0);
    cdev_del(&husky_cdev);   
    unregister_chrdev_region(devno, 1);
    printk(KERN_NOTICE "husky: firewall service (kernel module) has exited\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("U201814857");
MODULE_DESCRIPTION("Linux firewall homework");
