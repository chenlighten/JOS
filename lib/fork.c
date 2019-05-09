// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
    // 19-05-09: maybe buggy.
    if ((err & FEC_WR) != FEC_WR || 
            (((pte_t *)UVPT)[(uint32_t)addr >> 12] & PTE_COW) != PTE_COW)
        panic("This should not be handled in user pgfault()!\n");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
    // 19-05-09
	addr = ROUNDDOWN(addr, PGSIZE);
    if (sys_page_alloc(0, PFTEMP, PTE_W|PTE_U|PTE_P) < 0) {
        panic("sys_page_alloc() failed in pgfault().\n");
    }
    memcpy(PFTEMP, addr, PGSIZE);
	// This is not neccesary, as sys_page_map will complete this function.
    if (sys_page_unmap(0, addr) < 0) {
        panic("sys_page_unmap() failed in pgfault().\n");
    }
    if (sys_page_map(0, PFTEMP, 0, addr, PTE_U|PTE_W|PTE_P) < 0) {
        panic("sys_page_map() failed in pgfault().\n");
    }
	// This is actually also not neccesary.
	if (sys_page_unmap(0, PFTEMP) < 0) {
		panic("sys_page_map() 2 failed in pgfault().\n");
	}

	// panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int perm;

	// LAB 4: Your code here.
	// 19-05-09
	perm = ((pte_t *)UVPT)[pn*PGSIZE >> 12] & 0x00000FFF;
	if ((perm & (PTE_W|PTE_COW)) != 0) {
		if (sys_page_map(0, (void *)(pn*PGSIZE), envid, (void *)(pn*PGSIZE), perm|PTE_COW) < 0) {
			panic("sys_page_map() failed in duppage.\n");
		}
		// Map our page to copy on wirte too.
		if (sys_page_map(0, (void *)(pn*PGSIZE), 0, (void *)(pn*PGSIZE), perm|PTE_COW) < 0) {
			panic("sys_page_map() failed in duppage.\n");
		}
	}
	else {
		if (sys_page_map(0, (void *)(pn*PGSIZE), envid, (void *)(pn*PGSIZE), perm) < 0) {
			panic("sys_page_map() failed in duppage,\n");
		}
	}
	// panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
    // 19-05-09
	// Copy what it does in dumbfork.c.
	extern unsigned char end[];
    envid_t envid;
    set_pgfault_handler(pgfault);
    envid = sys_exofork();
	if (envid < 0) {
		panic("sys_exofork() failed in fork() : %e\n", envid);
	}
	if (envid == 0) {
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	for (uint8_t *addr = (uint8_t*)UTEXT; addr < end; addr += PGSIZE) {
		// Don't copy exception stack.
		if (UXSTACKTOP - PGSIZE <= (uint32_t)addr && (uint32_t)addr < UXSTACKTOP)
			continue;
		duppage(envid, (uint32_t)addr);
	}
	// Allocate a page for child process's exception stack.
	sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_U|PTE_W|PTE_P);
	return 0;
	// panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
