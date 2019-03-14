// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Backtrace the stack", mon_backtrace },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;

    //       added on May 11th
    //       reserve a correct return address
    //       using asembly code violently to change the stack

    char str[256] = {0};
    int nstr = 0;
    uint32_t pret_addr;
    // address of return address
    uint32_t addr_of_raddr;
    uint32_t ebp;    
    int i;

	// Your code here.
	// added on May 10th
	
	pret_addr = read_pretaddr();    
	ebp = read_ebp();
	addr_of_raddr = ebp + 4;
	for(i = 0; i < 256; i++) {
		str[i] = ' ';
	}
	str[246] = str[98] = str[18] = str[9] = '%';
	str[247] = str[99] = str[19] = str[10] = 'n';
	str[248] = '\0';

	// use %edi to store the correct return address
	// because %ebx won't be changed after calling a function
	__asm __volatile("mov 4(%ebp), %ebx\n\t");

	cprintf(str,
		addr_of_raddr + 1,
		addr_of_raddr + 2,
		addr_of_raddr + 0,
		addr_of_raddr + 3);
	/* *((uint32_t *)addr_of_raddr) = 0xf010095e; */

    //       added on May 11th
    //       reserve a correct return address
    //       using asembly code violently to change the stack
    
    __asm__ __volatile__("mov -8(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -12(%ebp)\n\t");
    __asm __volatile("mov -4(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -8(%ebp)\n\t");
    __asm __volatile("mov (%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -4(%ebp)\n\t");
    __asm __volatile("mov 4(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, (%ebp)\n\t");
    __asm __volatile("mov %ebx, 4(%ebp)\n\t");
    __asm __volatile("sub $4, %ebp\n\t");
    __asm __volatile("sub $4, %esp\n\t");

}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	overflow_me();
    	cprintf("Backtrace success\n");
	uint32_t ebp, eip;
        struct Eipdebuginfo info;
        // function name traced
        // 128 bytes shall be enough
        char fn_name[128];
        cprintf("Stack backtrace:\n");
        for(ebp = read_ebp(); ebp; ebp = *((uint32_t *)ebp)) {
                eip = *((uint32_t *)ebp + 1);
                cprintf("eip %08x  ebp %08x  args %08x %08x %08x %08x %08x\n",
                        eip,
                        ebp,
                        *((uint32_t *)ebp + 2),
                        *((uint32_t *)ebp + 3),
                        *((uint32_t *)ebp + 4),
                        *((uint32_t *)ebp + 5),
                        *((uint32_t *)ebp + 6));

                if(debuginfo_eip((uintptr_t)eip,  &info) >= 0) {
                        strcpy(fn_name, info.eip_fn_name);
                        fn_name[info.eip_fn_namelen] = '\0';
                        cprintf("\t%s:%d %s+%d\n",
                                info.eip_file,
                                info.eip_line,
                                fn_name,
                                eip - info.eip_fn_addr);
                }
        }
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
