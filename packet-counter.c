#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/jhash.h>
#include <linux/if_arp.h>

/* Define pr_fmt for consistent logging */
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define MODULE_NAME "l2packet_counter"
#define HASH_TABLE_BITS 8
#define RESET_INTERVAL_SEC 20

/* Module parameters */
static char *interface = "eth0";
module_param(interface, charp, 0444);
MODULE_PARM_DESC(interface, "Network interface to monitor (default: eth0)");

/* Hash table entry structure */
struct mac_entry {
    u8 mac_addr[ETH_ALEN];
    atomic64_t packet_count;
    struct hlist_node hash_node;
    struct rcu_head rcu;
};

/* Global variables with underscore suffix */
static struct net_device *monitored_dev_;
static DEFINE_HASHTABLE(mac_hash_table_, HASH_TABLE_BITS);
static DEFINE_SPINLOCK(hash_lock_);
static struct timer_list reset_timer_;
static struct proc_dir_entry *proc_entry_;
static atomic64_t total_packets_;

/* Function prototypes */
static rx_handler_result_t packet_counter_rx_handler(struct sk_buff **pskb);
static void reset_statistics_timer(struct timer_list *timer);
static void free_mac_entry_rcu(struct rcu_head *rcu);
static struct mac_entry *find_or_create_mac_entry(const u8 *mac_addr);
static void clear_hash_table(void);
static int register_rx_handler_for_device(const char *device_name);
static void unregister_rx_handler_for_device(void);

/* Hash function for MAC address */
static u32 mac_hash(const u8 *mac_addr)
{
    return jhash(mac_addr, ETH_ALEN, 0);
}

/* RCU callback to free mac_entry */
static void free_mac_entry_rcu(struct rcu_head *rcu)
{
    struct mac_entry *entry = container_of(rcu, struct mac_entry, rcu);
    kfree(entry);
}

/* Find existing MAC entry or create new one (lock-free for reads, minimal locking for writes) */
static struct mac_entry *find_or_create_mac_entry(const u8 *mac_addr)
{
    struct mac_entry *entry;
    struct mac_entry *new_entry = NULL;
    u32 hash_key = mac_hash(mac_addr);
    bool found = false;

    /* First check - we're already under RCU read lock from RX handler context */
    hash_for_each_possible_rcu(mac_hash_table_, entry, hash_node, hash_key) {
        if (ether_addr_equal(entry->mac_addr, mac_addr)) {
            found = true;
            break;
        }
    }

    if (found)
        return entry;

    /* Entry not found, need to create new one */
    new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
    if (!new_entry)
        return NULL;

    memcpy(new_entry->mac_addr, mac_addr, ETH_ALEN);
    /* packet_count, hash_node, and rcu are already zero-initialized by kzalloc */

    /* Critical section for insertion */
    spin_lock(&hash_lock_);

    /* Double-check if entry was created by another CPU */
    hash_for_each_possible_rcu(mac_hash_table_, entry, hash_node, hash_key) {
        if (ether_addr_equal(entry->mac_addr, mac_addr)) {
            found = true;
            break;
        }
    }

    if (found) {
        /* Another CPU created the entry, free our allocation */
        spin_unlock(&hash_lock_);
        kfree(new_entry);
        return entry;
    }

    /* Insert new entry using hash table macro */
    hash_add_rcu(mac_hash_table_, &new_entry->hash_node, hash_key);
    spin_unlock(&hash_lock_);

    return new_entry;
}

/* RX handler function */
static rx_handler_result_t packet_counter_rx_handler(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    struct ethhdr *eth_header;
    struct mac_entry *entry;

    if (!skb)
        return RX_HANDLER_PASS;

    /* Ensure we have ethernet header */
    if (!skb_mac_header_was_set(skb))
        return RX_HANDLER_PASS;

    /* Additional safety check - ensure we have enough data for ethernet header */
    if (skb->len < ETH_HLEN)
        return RX_HANDLER_PASS;

    eth_header = eth_hdr(skb);
    if (!eth_header)
        return RX_HANDLER_PASS;

    /* Skip multicast and broadcast frames for cleaner statistics */
    if (is_multicast_ether_addr(eth_header->h_source))
        return RX_HANDLER_PASS;

    /* Update total packet counter */
    atomic64_inc(&total_packets_);

    /* Find or create MAC entry and increment counter atomically */
    entry = find_or_create_mac_entry(eth_header->h_source);
    if (entry)
        atomic64_inc(&entry->packet_count);

    return RX_HANDLER_PASS;
}

/* Clear hash table and free all entries */
static void clear_hash_table(void)
{
    struct mac_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&hash_lock_);
    hash_for_each_safe(mac_hash_table_, bkt, tmp, entry, hash_node) {
        hash_del_rcu(&entry->hash_node);
        call_rcu(&entry->rcu, free_mac_entry_rcu);
    }
    spin_unlock(&hash_lock_);

    /* Reset total counter */
    atomic64_set(&total_packets_, 0);
}

/* Timer callback to reset statistics */
static void reset_statistics_timer(struct timer_list *timer)
{
    pr_info("Resetting statistics\n");
    clear_hash_table();

    /* Schedule next reset */
    mod_timer(&reset_timer_, jiffies + RESET_INTERVAL_SEC * HZ);
}

/* Proc file operations */
static int packet_counter_proc_show(struct seq_file *m, void *v)
{
    struct mac_entry *entry;
    int bkt;
    u64 total = atomic64_read(&total_packets_);

    seq_printf(m, "Interface: %s\n", interface);
    seq_printf(m, "Total packets: %llu\n", total);
    seq_printf(m, "MAC Address Statistics:\n");
    seq_printf(m, "%-18s %s\n", "MAC Address", "Packet Count");
    seq_printf(m, "%-18s %s\n", "-------------------", "------------");

    /* We're in process context here, so we need explicit RCU lock */
    rcu_read_lock();
    hash_for_each_rcu(mac_hash_table_, bkt, entry, hash_node) {
        u64 count = atomic64_read(&entry->packet_count);
        seq_printf(m, "%02x:%02x:%02x:%02x:%02x:%02x %12llu\n",
                   entry->mac_addr[0], entry->mac_addr[1],
                   entry->mac_addr[2], entry->mac_addr[3],
                   entry->mac_addr[4], entry->mac_addr[5],
                   count);
    }
    rcu_read_unlock();

    return 0;
}

static int packet_counter_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, packet_counter_proc_show, NULL);
}

static ssize_t packet_counter_proc_write(struct file *file, const char __user *buffer,
                                      size_t count, loff_t *pos)
{
    char cmd[32];

    if (count > sizeof(cmd) - 1)
        return -EINVAL;

    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;

    cmd[count] = '\0';

    /* Remove trailing newline */
    if (count > 0 && cmd[count - 1] == '\n')
        cmd[count - 1] = '\0';

    if (strcmp(cmd, "reset") == 0) {
        pr_info("Manual statistics reset\n");
        clear_hash_table();
        return count;
    }

    return -EINVAL;
}

static const struct proc_ops packet_counter_proc_ops = {
    .proc_open = packet_counter_proc_open,
    .proc_read = seq_read,
    .proc_write = packet_counter_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Function to register RX handler for a network device */
static int register_rx_handler_for_device(const char *device_name)
{
    int ret = 0;

    /* Find network device */
    monitored_dev_ = dev_get_by_name(&init_net, device_name);
    if (!monitored_dev_) {
        pr_err("Cannot find network interface %s\n", device_name);
        return -ENODEV;
    }

    /* Skip loopback and other non-Ethernet devices */
    if (monitored_dev_->type != ARPHRD_ETHER) {
        pr_err("Interface %s is not an Ethernet device (type: %d)\n",
               device_name, monitored_dev_->type);
        dev_put(monitored_dev_);
        monitored_dev_ = NULL;
        return -EINVAL;
    }

    /* Skip loopback device explicitly */
    if (monitored_dev_->flags & IFF_LOOPBACK) {
        pr_err("Interface %s is a loopback device\n", device_name);
        dev_put(monitored_dev_);
        monitored_dev_ = NULL;
        return -EINVAL;
    }

    /* Additional check for device name patterns to catch virtual devices */
    if (strncmp(device_name, "lo", 2) == 0) {
        pr_err("Loopback interface %s not supported\n", device_name);
        dev_put(monitored_dev_);
        monitored_dev_ = NULL;
        return -EINVAL;
    }

    pr_info("Monitoring Ethernet interface %s (type: %d, flags: 0x%x)\n",
            device_name, monitored_dev_->type, monitored_dev_->flags);

    /* Register RX handler */
    ret = netdev_rx_handler_register(monitored_dev_, packet_counter_rx_handler, NULL);
    if (ret) {
        pr_err("Failed to register RX handler for %s: %d\n", device_name, ret);
        dev_put(monitored_dev_);
        monitored_dev_ = NULL;
        return ret;
    }

    pr_info("Successfully registered RX handler for interface %s\n", device_name);
    return 0;
}

/* Function to unregister RX handler */
static void unregister_rx_handler_for_device(void)
{
    if (monitored_dev_) {
        pr_info("Unregistering RX handler for interface %s\n", monitored_dev_->name);

        netdev_rx_handler_unregister(monitored_dev_);
        dev_put(monitored_dev_);
        monitored_dev_ = NULL;
    }
}

/* Module initialization */
static int __init packet_counter_init(void)
{
    int ret = 0;

    pr_info("Loading module for interface %s\n", interface);

    /* Initialize hash table */
    hash_init(mac_hash_table_);
    atomic64_set(&total_packets_, 0);

    /* Register RX handler for the specified device */
    ret = register_rx_handler_for_device(interface);
    if (ret)
        return ret;

    /* Create proc entry */
    proc_entry_ = proc_create(MODULE_NAME, 0644, NULL, &packet_counter_proc_ops);
    if (!proc_entry_) {
        pr_err("Failed to create proc entry\n");
        unregister_rx_handler_for_device();
        return -ENOMEM;
    }

    /* Setup timer for periodic reset */
    timer_setup(&reset_timer_, reset_statistics_timer, 0);
    mod_timer(&reset_timer_, jiffies + RESET_INTERVAL_SEC * HZ);

    pr_info("Module loaded successfully\n");
    return 0;
}

/* Module cleanup */
static void __exit packet_counter_exit(void)
{
    pr_info("Unloading module\n");

    /* Delete timer */
    del_timer_sync(&reset_timer_);

    /* Remove proc entry */
    if (proc_entry_)
        proc_remove(proc_entry_);

    /* Unregister RX handler and release device */
    unregister_rx_handler_for_device();

    /* Clear hash table and wait for RCU grace period */
    clear_hash_table();
    synchronize_rcu();

    pr_info("Module unloaded\n");
}

module_init(packet_counter_init);
module_exit(packet_counter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrejs Glazkovs");
MODULE_DESCRIPTION("Layer 2 packet counter by MAC address");
MODULE_VERSION("1.0");
