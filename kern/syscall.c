/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
    // Added on Apirl 8
    user_mem_assert(curenv, (const void *)s, len, PTE_U);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	if (e == curenv)
		cprintf("[%08x] exiting gracefully\n", curenv->env_id);
	else
		cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	env_destroy(e);
	return 0;
}

static int
sys_map_kernel_page(void* kpage, void* va)
{
    int r;
    struct PageInfo* p = pa2page(PADDR(kpage));
    if (p == NULL)
        return E_INVAL;
    r = page_insert(curenv->env_pgdir, p, va, PTE_U | PTE_W);
    return r;
}

static int
sys_sbrk(uint32_t inc)
{
    // LAB3: your code here.
    // Added on April 8.
    void *begin = (void *)ROUNDDOWN(curenv->env_pbrk, PGSIZE);
    void *end = (void *)ROUNDUP(curenv->env_pbrk + inc, PGSIZE);
    pte_t *pte_ptr;
    struct PageInfo *pp;

    while (begin < end) {
        // If virtual address begin is not mapped
        if(!page_lookup(curenv->env_pgdir, begin, &pte_ptr)) {
            // Allocate a physical page
            pp = page_alloc(ALLOC_ZERO);
            if(!pp) {
                panic("Page alloc failed at sys_sbrk().");
            }
            pp->pp_ref++;
            // Permission should be writable
            page_insert(curenv->env_pgdir, pp, begin, PTE_U | PTE_W);
        }
        begin += PGSIZE;
    }
    
    return (int)(curenv->env_pbrk += inc);
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.


	switch (syscallno) {
        case SYS_cputs:
            sys_cputs((const char *)a1, (size_t)a2);
            // Return the length of the output string.
            return (int32_t)a2;

        case SYS_cgetc:
            return (int32_t)sys_cgetc();

        case SYS_getenvid:
            return (int32_t)sys_getenvid();

        case SYS_env_destroy:
            return (int32_t)sys_env_destroy(sys_getenvid());

        case SYS_map_kernel_page:
            return (int32_t)sys_map_kernel_page((void *)a1, (void *)a2);

        case SYS_sbrk:
            return (int32_t)sys_sbrk((uint32_t)a1);

	    default:
		    return -E_INVAL;
	}
}

