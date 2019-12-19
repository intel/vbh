// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/string.h>

#include "hypervisor_introspection.h"

#define KERNEL_CODE								"Kernel code"
#define KERNEL_DATA								"Kernel data"
#define KERNEL_BSS								"Kernel bss"
#define SYSTEM_RAM								"System RAM"

#define __RESOURCE_FOUND_BY_NAME(res, n) (res && strcmp(res->name, n) == 0)

#define __SUCCESS(x)					 ((x) >= 0)

static int set_kcode_protection(struct resource *target)
{
	u8 read, write, execute;

	u64 g_kcode_paddr_start, g_kcode_paddr_end, addr;

	int status = -1;

	write = 0;

	read = execute = 1;

	g_kcode_paddr_start = (target->start);

	g_kcode_paddr_end = target->end;

	for (addr = g_kcode_paddr_start; (addr+PAGE_SIZE) < g_kcode_paddr_end;
		addr += PAGE_SIZE) {
		status = hvi_set_ept_page_protection(addr, read, write, execute);
		pr_err("Set policy on addr->0x%llx: read=%d, write=%d, execute=%d.\n", addr, read, write, execute);
	}

	return status;
}

/*
 *Find the first resource which name matches.a
 **/
static int get_resource_by_name(const char *name, struct resource **resource)
{
	int found = -1;

	struct resource *entry, *child;

	entry = iomem_resource.child;

	while (1) {
		if (entry == NULL)
			break;

		if (__RESOURCE_FOUND_BY_NAME(entry, SYSTEM_RAM)) {
			while (1) {
				child = entry->child;

				if (child == NULL)
					break;

				if (__RESOURCE_FOUND_BY_NAME(child, name)) {
					pr_err("<hvi>: Found kernel code region: start = 0x%llx, end = 0x%llx.\n",
						child->start, child->end);
					*resource = child;
					found = 1;
					break;
				}

				entry = child->sibling;
			}
		}

		entry = entry->sibling;
	}

	return found;
}

int hvi_configure_kernel_code_protection(void)
{
	struct resource *target;

	int status = -1;

	if (__SUCCESS(get_resource_by_name(KERNEL_CODE, &target))) {
		pr_err("<hvi>Found %s region.  Apply policy...\n",
			target->name);

		status = set_kcode_protection(target);
	}

	return status;
}
