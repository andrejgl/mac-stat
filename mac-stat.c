#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>


MODULE_DESCRIPTION("L2 MAC stat module");
MODULE_AUTHOR("Andrejs Glazkovs");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

#define PROCFS_NAME "mac-stat"

#define MACSTAT_HASH_BITS 8
#define MACSTAT_HASH_SIZE (1 << MACSTAT_HASH_BITS)
#define MAC_STAT_RESET_INTERVAL 10000 /* ms */
static char const *DEV_NAME = "enp0s8";

struct mac_data_t
{
        u8 mac[ETH_ALEN]; // key
        atomic_long_t counter;

        struct hlist_node hlist;
};

static struct net_device *dev_ = NULL;
DECLARE_HASHTABLE(mac_map_, MACSTAT_HASH_BITS);
static struct timer_list reset_timer_;

// HASH TABLE

static inline u32 mac_stat_hash(u8 *mac)
{
        return hash_32(jhash(mac, ETH_ALEN, 0),
                       MACSTAT_HASH_BITS);
}

static struct mac_data_t *
mac_stat_lookup(u8 *key, u32 hash)
{
        struct mac_data_t *val;

        hash_for_each_possible_rcu(mac_map_, val, hlist, hash)
        {
                if (ether_addr_equal(key, val->mac))
                {
                        return val;
                }
        }
        return NULL;
}

static void mac_map_cleanup(void)
{
        unsigned bkt;
        struct mac_data_t *mac_data;
        struct hlist_node *tmp;

        rcu_read_lock();
        hash_for_each_safe(mac_map_, bkt, tmp, mac_data, hlist)
        {
                hash_del_rcu(&mac_data->hlist);
                kfree(mac_data);
        }
        rcu_read_unlock();
}

// PROC FILE
static struct proc_dir_entry *proc_file_;

static int mac_stat_show(struct seq_file *s, void *v)
{
        seq_printf(s, "dev name: %s\n", dev_->name);
        seq_printf(s, "HWAddress\t\tCounter\tHash Index\n");

        unsigned bkt;
        struct mac_data_t *mac_data;

        rcu_read_lock();
        hash_for_each_rcu(mac_map_, bkt, mac_data, hlist)
        {
                seq_printf(s, "%pM\t%lu\t%u\n"
                        , mac_data->mac
                        , atomic_long_read(&(mac_data->counter))
                        , mac_stat_hash(mac_data->mac)
                        );
        }

        struct rtnl_link_stats64 temp;
        const struct rtnl_link_stats64 *stats = dev_get_stats(dev_, &temp);
        rcu_read_unlock();

        seq_printf(s, "dev stat %6s: %7llu \n",
                dev_->name, stats->rx_packets);

        return 0;
}

static int mac_stat_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, mac_stat_show, NULL);
};

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_fops = {
    .proc_open = mac_stat_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations proc_file_fops = {
    .open = mac_stat_proc_open,
    .read = seq_read,
    .lseek = seq_lseek,
    .release = single_release,
};
#endif

// L2 frame handler
/* called under rcu_read_lock() from netif_receive_skb */
static rx_handler_result_t mac_stat_handle_frame(struct sk_buff **pskb)
{
        int res = RX_HANDLER_PASS;
        struct sk_buff *skb = *pskb;
        struct skb_shared_info *shinfo = skb_shinfo(skb);

        u32 mac_hash = mac_stat_hash(eth_hdr(skb)->h_source);

        struct mac_data_t *mac_data = mac_stat_lookup(eth_hdr(skb)->h_source, mac_hash);
        if (!mac_data)
        {
                mac_data = kzalloc(sizeof(struct mac_data_t), GFP_KERNEL);
                memcpy(mac_data->mac, eth_hdr(skb)->h_source, ETH_ALEN);
                atomic_long_set(&(mac_data->counter), 1 + shinfo->nr_frags);
                hash_add_rcu(mac_map_, &mac_data->hlist, mac_hash);
        }
        else
        {
                atomic_long_add(1 + shinfo->nr_frags, &mac_data->counter);
        }

        return res;
}

static int mac_stat_setup_device(const char *name)
{
        int res = 0;

        rtnl_lock();
        dev_ = __dev_get_by_name(&init_net, name);
        if (!dev_)
        {
                pr_err("can't find device: %s\n", name);
                res = -ENODEV;
        }
        else
        {
                res = netdev_rx_handler_register(dev_, mac_stat_handle_frame,
                                                 NULL);
                if (res < 0)
                {
                        pr_err("Error %d calling netdev_rx_handler_register for %s dev\n", res, name);
                        dev_ = NULL;
                }
        }
        rtnl_unlock();

        return res;
}

static void mac_stat_cleanup(void)
{
        rtnl_lock();
        if (dev_)
        {
                netdev_rx_handler_unregister(dev_);
                dev_ = NULL;
        }
        rtnl_unlock();

        mac_map_cleanup();
}

static void reset_timer_cb(struct timer_list *timer)
{
        mac_map_cleanup();
        mod_timer(&reset_timer_, jiffies + msecs_to_jiffies(MAC_STAT_RESET_INTERVAL));
}

static int __init mac_stat_init(void)
{
        pr_debug("[%s]: FUNC:%s\n", __FILE__, __FUNCTION__);

        int res;
        res = mac_stat_setup_device(DEV_NAME);

        timer_setup(&reset_timer_, reset_timer_cb, 0);
        mod_timer(&reset_timer_, jiffies + msecs_to_jiffies(MAC_STAT_RESET_INTERVAL));

        proc_file_ = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops);
        if (NULL == proc_file_)
        {
                pr_alert("Error:Could not initialize /proc/%s\n", PROCFS_NAME);
                return -ENOMEM;
        }

        return res;
}

static void __exit mac_stat_exit(void)
{
        pr_debug("[%s]: FUNC:%s\n", __FILE__, __FUNCTION__);

        proc_remove(proc_file_);
        del_timer(&reset_timer_);
        mac_stat_cleanup();
}

module_init(mac_stat_init);
module_exit(mac_stat_exit);
