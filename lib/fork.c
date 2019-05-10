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
		!(uvpd[PDX(addr)] & PTE_P) || 
		!(uvpt[PGNUM(addr)] & PTE_P) || 
		!(uvpt[PGNUM(addr)] & PTE_COW)) {
		cprintf("va:%x, err:%x, perm:%x", addr, err, uvpt[PGNUM(addr)]);
        panic("This should not be handled in user pgfault()!\n");
	}

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
	int r;
	// static int debug_duppage_time = 1;
	// cprintf("This is the %d times to call duppage.\n", debug_duppage_time++);

	// LAB 4: Your code here.
	// 19-05-09
	perm = uvpt[pn] & 0x00000FFF;
	// We have set PTE_A
	// cprintf("perm is %x\n", perm);
	if (perm & (PTE_W|PTE_COW)) {
		if ((r = sys_page_map(0, (void *)(pn*PGSIZE), envid, (void *)(pn*PGSIZE), PTE_P|PTE_U|PTE_COW)) < 0) {
			panic("sys_page_map() failed in duppage(): %e", r);
		}
		// Map our page to copy on wirte too.
		if ((r = sys_page_map(0, (void *)(pn*PGSIZE), 0, (void *)(pn*PGSIZE), PTE_P|PTE_U|PTE_COW)) < 0) {
			panic("sys_page_map() failed in duppage(): %e", r);
		}
	}
	else {
		if ((r = sys_page_map(0, (void *)(pn*PGSIZE), envid, (void *)(pn*PGSIZE), PTE_U|PTE_P)) < 0) {
			panic("sys_page_map() failed in duppage(): %e", r);
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

	// This is used to set the env_pgfault_upcall for child process
	// The env_pgfault_upcall of parent process will be set by set_pgfault_handler().
	extern void _pgfault_upcall();

    envid_t envid;
    set_pgfault_handler(pgfault);
	envid = sys_exofork();

	if (envid < 0) {
		panic("sys_exofork() failed in fork() : %e\n", envid);
	}
	// For child environment, as dumbfork.c does.
	if (envid == 0) {
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	// Set env_pgfault_upcall for child process.
	// ** Not pgfault_handler! **
	if (sys_env_set_pgfault_upcall(envid, _pgfault_upcall) < 0) {
		panic("sys_env_set_pgfault_upcall() failed in fork().");
	}

	// Copy what dumbfork.c does.
	for (uint32_t addr = UTEXT; addr < UTOP; addr += PGSIZE) {
		// Don't copy exception stack.
		if (UXSTACKTOP - PGSIZE <= addr && addr < UXSTACKTOP)
			continue;
		// Copy the page that:
		// 1) the page table exists;
		// 2) itself exitsts;
		// 3) is user-accessible.
		if ((uvpd[PDX(addr)] & PTE_P) && 
			(uvpt[PGNUM(addr)] & PTE_P) &&
			(uvpt[PGNUM(addr)] & PTE_U))
			duppage(envid, PGNUM(addr));
	}
	// Allocate a page for child process's exception stack.
	if (sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_U|PTE_W|PTE_P) < 0) {
		panic("sys_page_alloc() failed in fork().");
	}
	// Easy to forget it and spend 2 hours to fix it.
	sys_env_set_status(envid, ENV_RUNNABLE);

	return envid;
	// panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
