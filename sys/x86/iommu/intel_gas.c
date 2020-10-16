/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/* [remove rb tree] */
// #define	RB_AUGMENT(entry) dmar_gas_augment_entry(entry)

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/memdesc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/rman.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/vmem.h>
#include <dev/pci/pcivar.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/uma.h>
#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <x86/include/busdma_impl.h>
#include <x86/iommu/intel_reg.h>
#include <x86/iommu/busdma_dmar.h>
#include <dev/pci/pcireg.h>
#include <x86/iommu/intel_dmar.h>

/*
 * Guest Address Space management.
 */

static uma_zone_t dmar_map_entry_zone;

static void
intel_gas_init(void)
{

	dmar_map_entry_zone = uma_zcreate("DMAR_MAP_ENTRY",
	    sizeof(struct dmar_map_entry), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NODUMP);
}
SYSINIT(intel_gas, SI_SUB_DRIVERS, SI_ORDER_FIRST, intel_gas_init, NULL);

struct dmar_map_entry *
dmar_gas_alloc_entry(struct dmar_domain *domain, u_int flags)
{
	struct dmar_map_entry *res;

	KASSERT((flags & ~(DMAR_PGF_WAITOK)) == 0,
	    ("unsupported flags %x", flags));

	res = uma_zalloc(dmar_map_entry_zone, ((flags & DMAR_PGF_WAITOK) !=
	    0 ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (res != NULL) {
		res->domain = domain;
		atomic_add_int(&domain->entries_cnt, 1);
	}
	return (res);
}

void
dmar_gas_free_entry(struct dmar_domain *domain, struct dmar_map_entry *entry)
{

	KASSERT(domain == entry->domain,
	    ("mismatched free domain %p entry %p entry->domain %p", domain,
	    entry, entry->domain));
	atomic_subtract_int(&domain->entries_cnt, 1);
	uma_zfree(dmar_map_entry_zone, entry);
}

void
dmar_gas_init_domain(struct dmar_domain *domain)
{
	DMAR_DOMAIN_LOCK(domain);
	KASSERT(domain->entries_cnt == 2, ("dirty domain %p", domain));

	vmem_size_t quantum = DMAR_PAGE_SIZE;
	domain->iova_arena = vmem_create("iova", 0, rounddown(domain->end, quantum),
		quantum, quantum << 4, M_WAITOK);
	domain->flags |= DMAR_DOMAIN_GAS_INITED;
	DMAR_DOMAIN_UNLOCK(domain);
}

void
dmar_gas_fini_domain(struct dmar_domain *domain)
{
	DMAR_DOMAIN_ASSERT_LOCKED(domain);
	vmem_destroy(domain->iova_arena);
	domain->iova_arena = NULL;
}

struct dmar_gas_match_args {
	struct dmar_domain *domain;
	dmar_gaddr_t size;
	int offset;
	const struct bus_dma_tag_common *common;
	u_int gas_flags;
	struct dmar_map_entry *entry;
};

static int
dmar_gas_alloc_region(struct dmar_domain *domain, struct dmar_map_entry *entry,
    u_int flags)
{
	if ((entry->start & DMAR_PAGE_MASK) != 0 ||
	    (entry->end & DMAR_PAGE_MASK) != 0)
		return (EINVAL);
	if (entry->start >= entry->end)
		return (EINVAL);
	if (entry->end >= domain->end)
		return (EINVAL);

	printf("reserve request of range [%lx, %lx] not supported, so fuck you\n",
	    entry->start, entry->end);

	if ((flags & DMAR_GM_RMRR) != 0)
		entry->flags = DMAR_MAP_ENTRY_RMRR;

	return (0);
}

void
dmar_gas_free_space(struct dmar_domain *domain, struct dmar_map_entry *entry)
{
	vmem_free(domain->iova_arena, entry->start,
		    entry->end - entry->start);
	entry->flags &= ~(DMAR_MAP_ENTRY_MAP | DMAR_MAP_ENTRY_RMRR);
}

int
dmar_gas_map(struct dmar_domain *domain,
    const struct bus_dma_tag_common *common, dmar_gaddr_t size, int offset,
    u_int eflags, u_int flags, vm_page_t *ma, struct dmar_map_entry **res)
{
	struct dmar_map_entry *entry;
	vmem_addr_t start;
	int error;

	KASSERT((flags & ~(DMAR_GM_CANWAIT | DMAR_GM_CANSPLIT)) == 0,
	    ("invalid flags 0x%x", flags));

	entry = dmar_gas_alloc_entry(domain, (flags & DMAR_GM_CANWAIT) != 0 ?
	    DMAR_PGF_WAITOK : 0);
	if (entry == NULL)
		return (ENOMEM);

	error = vmem_alloc(domain->iova_arena, size,
				    M_BESTFIT | ((flags & DMAR_GM_CANWAIT) != 0 ?
					M_WAITOK : M_NOWAIT),
				    &start);
	if(error != 0)
	{
		printf("FUCK!!! No memory for iova allocation\n");
		return (ENOMEM);
	}

	entry->start = start;
	entry->end = start + size;
	entry->flags |= eflags;

	error = domain_map_buf(domain, entry->start, entry->end - entry->start,
	    ma,
	    ((eflags & DMAR_MAP_ENTRY_READ) != 0 ? DMAR_PTE_R : 0) |
	    ((eflags & DMAR_MAP_ENTRY_WRITE) != 0 ? DMAR_PTE_W : 0) |
	    ((eflags & DMAR_MAP_ENTRY_SNOOP) != 0 ? DMAR_PTE_SNP : 0) |
	    ((eflags & DMAR_MAP_ENTRY_TM) != 0 ? DMAR_PTE_TM : 0),
	    (flags & DMAR_GM_CANWAIT) != 0 ? DMAR_PGF_WAITOK : 0);
	if (error == ENOMEM) {
		dmar_domain_unload_entry(entry, true);
		return (error);
	}
	KASSERT(error == 0,
	    ("unexpected error %d from domain_map_buf", error));

	*res = entry;
	return (0);
}

int
dmar_gas_map_rmrr_region(struct dmar_domain *domain, struct dmar_map_entry *entry,
    u_int eflags, u_int flags, vm_page_t *ma)
{
	dmar_gaddr_t start;
	int error;

	KASSERT(entry->flags == 0, ("used RMRR entry %p %p %x", domain,
	    entry, entry->flags));
	KASSERT((flags & ~(DMAR_GM_CANWAIT | DMAR_GM_RMRR)) == 0,
	    ("invalid flags 0x%x", flags));

	start = entry->start;
	error = dmar_gas_alloc_region(domain, entry, flags);
	if (error != 0) {
		return (error);
	}
	entry->flags |= eflags;
	if (entry->end == entry->start)
		return (0);

	error = domain_map_buf(domain, entry->start, entry->end - entry->start,
	    ma + OFF_TO_IDX(start - entry->start),
	    ((eflags & DMAR_MAP_ENTRY_READ) != 0 ? DMAR_PTE_R : 0) |
	    ((eflags & DMAR_MAP_ENTRY_WRITE) != 0 ? DMAR_PTE_W : 0) |
	    ((eflags & DMAR_MAP_ENTRY_SNOOP) != 0 ? DMAR_PTE_SNP : 0) |
	    ((eflags & DMAR_MAP_ENTRY_TM) != 0 ? DMAR_PTE_TM : 0),
	    (flags & DMAR_GM_CANWAIT) != 0 ? DMAR_PGF_WAITOK : 0);
	if (error == ENOMEM) {
		dmar_domain_unload_entry(entry, false);
		return (error);
	}
	KASSERT(error == 0,
	    ("unexpected error %d from domain_map_buf", error));

	return (0);
}

int
dmar_gas_reserve_region(struct dmar_domain *domain, dmar_gaddr_t start,
    dmar_gaddr_t end)
{
	struct dmar_map_entry *entry;
	int error;

	entry = dmar_gas_alloc_entry(domain, DMAR_PGF_WAITOK);
	entry->start = start;
	entry->end = end;
	error = dmar_gas_alloc_region(domain, entry, DMAR_GM_CANWAIT);
	if (error == 0)
		entry->flags |= DMAR_MAP_ENTRY_UNMAPPED;
	if (error != 0)
		dmar_gas_free_entry(domain, entry);
	return (error);
}
