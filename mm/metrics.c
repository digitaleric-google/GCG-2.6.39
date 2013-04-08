#include <linux/module.h>
#include <linux/gmetrics.h>

struct metric_stat {
	enum zone_stat_item ordinal;
	const char *name;
} metric_stats[] __initdata = {
	{ NR_ACTIVE_ANON, "active_anon"},
	{ NR_ACTIVE_FILE, "active_file"},
	{ NR_INACTIVE_ANON, "inactive_anon"},
	{ NR_INACTIVE_FILE, "inactive_file"},
	{ NR_UNEVICTABLE, "unevictable"},
	{ NR_MLOCK, "mlock"},
	{ NR_FREE_PAGES, "free_pages"},
	{ NR_FILE_MAPPED, "file_mapped"},
	{ NR_ANON_PAGES, "anon_pages"},
	{ NR_FILE_PAGES, "file_pages"},
	{ NR_FILE_DIRTY, "file_dirty"},
	{ NR_WRITEBACK, "writeback"},
	{ NR_SLAB_RECLAIMABLE, "slab_reclaimable"},
	{ NR_SLAB_UNRECLAIMABLE, "slab_unreclaimable"},
	{ NR_PAGETABLE, "pagetable"},
	{ NR_KERNEL_STACK, "kernel_stack"},
	{ NR_BOUNCE, "bounce"},
	{ NR_SHMEM, "shmem"},
	{ NR_DIRTIED, "dirtied"},
	{ NR_WRITTEN, "written"},
};

static struct list_head *registered_entries[MAX_NUMNODES * MAX_NR_ZONES *
					    ARRAY_SIZE(metric_stats)];
static int registered_entry_count;

static void __init remember_metric(struct list_head *entry)
{
	registered_entries[registered_entry_count++] = entry;
}

static void __init add_metric(int nid, int zonei, struct metric_stat *stat)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone = pgdat->node_zones + zonei;
	char buf[sizeof("nodeXXXX/zoneY/ZZZZZZZZZZZZZZZZZZZZZZZZZZZ")];
	struct list_head *entry;
	phys_addr_t paddr;

	sprintf(buf, "node%d/zone%d/%s", nid, zonei, stat->name);
	paddr = virt_to_phys(&zone->vm_stat[stat->ordinal].counter);

	entry = metric_register_ptr(buf, paddr, sizeof(atomic_long_t));
	if (entry && !IS_ERR(entry))
		remember_metric(entry);
}

static void __init register_zones(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int zonei;

	for (zonei = 0; zonei < pgdat->nr_zones; zonei++) {
		struct zone *zone = pgdat->node_zones + zonei;
		int i;

		if (!populated_zone(zone))
			continue;

		for (i = 0 ; i < ARRAY_SIZE(metric_stats); i++)
			add_metric(nid, zonei, &metric_stats[i]);
	}
}

static int __init mm_metrics_init(void)
{
	int nid;

	registered_entry_count = 0;
	for_each_node_state(nid, N_HIGH_MEMORY) {
		register_zones(nid);
	}

	return 0;
}

static void __exit mm_metrics_exit(void)
{
	int i;

	for (i = 0; i < registered_entry_count; i++)
		metric_unregister_ptr(registered_entries[i]);
}

module_init(mm_metrics_init);
module_exit(mm_metrics_exit);
