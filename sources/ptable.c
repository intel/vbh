// SPDX-License-Identifier: GPL-2.0

#include <linux/ioport.h>
#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */

#include "vmx_common.h"

#define EPT_MAX_LEVEL 4
#define EPT_LEVEL_STRIDE 9
#define EPT_STRIDE_MASK ((1 << EPT_LEVEL_STRIDE) - 1)
#define EPT_PAGE_MASK ((1 << 12) - 1)
#define EPT_LARGEPAGE_SUPPORTED 2
#define EPT_MAX_PAGING_LEVEL 4
#define EPT_PAGE_SHIFT 12
#define PAGE_SHIFT 12
#define PTE_READ 1
#define PTE_WRITE 2
#define PTE_EXECUTE 4
#define PTE_MEM_TYPE_WB 0x30
#define EPT_PTE_LARGE_PAGE (1 << 7)

static void set_ept_protection(void);

static void set_ept_protection(void)
{
	unsigned long *ept;

	// protect ept itself from any access or modifcation (rwx=0)
	ept = get_ept_entry(__pa(vmx_eptp_pml4));
	set_ept_entry_prot(ept, 0, 0, 0);
}

unsigned long level_to_pages(unsigned long level)
{
	return (1 << (level-1)*EPT_LEVEL_STRIDE);
}

int pfn_level_offset(unsigned long pfn, unsigned long level)
{
	return (pfn >> (level - 1)*EPT_LEVEL_STRIDE) & EPT_STRIDE_MASK;
}

u64 pte_table_addr(u64 pteval)
{
	return pteval & ~EPT_PAGE_MASK;
}

int highest_level_possible_for_addr(unsigned long pfn, unsigned long nr_pages)
{
	int support, level = 1;

	support = EPT_LARGEPAGE_SUPPORTED;

	while (support && !(pfn & EPT_STRIDE_MASK)) {
		nr_pages >>= EPT_LEVEL_STRIDE;
		if (!nr_pages)
			break;
		pfn >>= EPT_LEVEL_STRIDE;
		level++;
		support--;
	}
	return level;
}

unsigned long *pte_for_address(unsigned long pfn, unsigned long *target_level)
{
	unsigned long *pte;
	unsigned long level, offset;
	unsigned long *parent;
	unsigned long pte_pfn;

	parent = vmx_eptp_pml4;
	level = EPT_MAX_PAGING_LEVEL;

	while (1) {
		offset = pfn_level_offset(pfn, level);
		pte = &parent[offset];

		if (level == *target_level)
			break;

		if (!*pte) {
			u64 pteval;
			void *page;

			page = (void *)get_zeroed_page(GFP_KERNEL);
			pte_pfn = __pa(page) >> PAGE_SHIFT;
			//Todo: Add EPT memory type
			pteval = (pte_pfn << EPT_PAGE_SHIFT) | PTE_READ |
				PTE_WRITE | PTE_EXECUTE;
			*pte = pteval;
		}

		level--;
		parent = phys_to_virt(pte_table_addr(*pte));
	}

	// protect ept itself.
	//set_ept_protection();

	return pte;
}

int build_pte_guest_phys_addr(unsigned long start_pfn, long nr_pages)
{
	unsigned long *pte;
	unsigned long level;
	unsigned long pages;

	while (nr_pages > 0) {
		u64 pteval = 0;

		level = 1;
		pte = pte_for_address(start_pfn, &level);
		if (!pte)
			return -ENOMEM;

		pages = 1;
		if (level > 1) {
			pteval |= EPT_PTE_LARGE_PAGE;
			pages = level_to_pages(level);
		}

	    //Todo: Add EPT memory type
	    *pte = pteval | (start_pfn << EPT_PAGE_SHIFT) | PTE_MEM_TYPE_WB |
			PTE_READ | PTE_WRITE | PTE_EXECUTE;
		nr_pages -= pages;
		start_pfn += pages;
	}

	return 0;
}

void setup_ept_tables(void)
{
	// Parse iomem_resource for physical addres ranges
    // Parse only the siblings
	struct resource *root, *entry;
	unsigned long start, end;
	long nr_pages, size;

	root = &iomem_resource;
	entry = root->child;

	while (1) {
		// Round the size to 4k boundary
		pr_err("<EPT> Name: %s", entry->name);
	    start = (entry->start >> 12) << 12;
	    end = entry->end & 0xFFF;
		if (end)
			end = ((entry->end >> 12) << 12) + 0x1000;

		size = end - start;
		nr_pages = size >> 12;

		build_pte_guest_phys_addr((start >> PAGE_SHIFT), nr_pages);

		if (!entry->sibling)
			break;
		entry = entry->sibling;
	}

	// protect ept itself.
	set_ept_protection();
}

void dump_entries(u64 gpa)
{
	unsigned long pfn = gpa >> PAGE_SHIFT;
	u64 pteval;
	unsigned long level;
	unsigned long *parent;
	unsigned long offset;

	level = 4;
	parent = vmx_eptp_pml4;
	while (level > 0) {
		offset = pfn_level_offset(pfn, level);
		pteval = parent[offset];
		pr_err("level %lu pteval %llx\n", level, pteval);
		if ((pteval & EPT_PTE_LARGE_PAGE) == EPT_PTE_LARGE_PAGE)
			break;
		level--;
		parent = phys_to_virt(pte_table_addr(pteval));
	}
}

unsigned long *get_ept_entry(u64 gpa)
{
	unsigned long pfn = gpa >> PAGE_SHIFT;
	u64 pteval;
	unsigned long level;
	unsigned long *parent;
	unsigned long offset;

	level = 4;
	parent = vmx_eptp_pml4;
	while (level > 0) {
		offset = pfn_level_offset(pfn, level);
		pteval = parent[offset];
		if ((pteval & EPT_PTE_LARGE_PAGE) == EPT_PTE_LARGE_PAGE)
			break;
		level--;
		if (level == 0)
			break;
		parent = phys_to_virt(pte_table_addr(pteval));
	}

	return parent + offset;
}

void set_ept_entry_prot(unsigned long *entry, int read, int write, int execute)
{
	unsigned long prot, new_entry;

	prot = new_entry = 0;

	if (read)
		prot |= PTE_READ;
	if (write)
		prot |= PTE_WRITE;
	if (execute)
		prot |= PTE_EXECUTE;

	new_entry = *entry & (~(PTE_READ | PTE_WRITE | PTE_EXECUTE));
	new_entry |= prot;
	*entry = new_entry;
}

int get_ept_entry_prot(unsigned long entry)
{
	return entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE);
}
