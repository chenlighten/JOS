# JOS
JOS is a unix-like operating system in the very famous course mit 6.828, and this repo is my solution in the process of building JOS in that course. The whole project is devided into sevaral labs, and each of them deals with one or more important topic in operating system. 

Every lab is represented as a branch in this git repo, you can checkout to the corresbonding branch to see my solution to the labs.

SJTU added some additional problems and features to the original version of the lab, and this repo is in fact for the new version. Here is the homepage for the course https://ipads.se.sjtu.edu.cn/courses/os/.

You can also find a document or report that describes the design and solving process of each lab in the corresbonding branch. Here follows the document for lab1, and here is the homepage of lab1 https://ipads.se.sjtu.edu.cn/courses/os/labs/joslab1.html.

# Document of Lab1 for JOS

This document describes the design and implementation of my code in Lab1, as well as some problems and confusing points I met during the lab.

## 1 Dive into the Booting Process

This section is about my procedure of exploring Part I and part II. I list some of my understanding and puzzles of the booting process below. This section doesn't concern any code I write. T.A. can feel free to skip it.

After setting up the tools and the environmental, used gdb to follow the execution of every instruction of the booting process.

At the very beginning of the execution, gdb printed the information of the instructions with the following formation:
``` [f000:fff0]    0xffff0:	ljmp   $0xf000,$0xe05b ```
The ` [f000:fff0] ` on the left suggests that the CPU is now in real mode, using segment register `cs` and selector register `eip` together to determine the address of the instructions. The physical address is calculated as `16*cs + eip`, as we can see in the debugging information above that `0xffff0` just equals to `16*0xf000` + `0xfff0`.
Also, we can find that the first instruction executed is on address `0xffff0`, which is a very high address in the BIOS address space. And this instruction makes the control jumping to `0xfe05b`, which is a relatively low address in BIOS address space. So obviously the instructions being executed now are BIOS instructions rather than boot loader instructions.
After jumping to `fe05d`, CPU compares `0` with `cs:0x2f6c`(which means `16*cs + 0x2f6c`). If 0 is no more than `cs:0x2f6c`, the control will jump to 0xfc5cc. This may be some protection or testing process.

```
0xfe05b:        cmpl   $0x0,%cs:-0x2f6c
0xfe062:        jne    0xfc5cc
```

Then after some preparations the BIOS changed the real mode to protected mode:

```
0xfe066:        xor    %ax,%ax
0xfe068:        mov    %ax,%ss
0xfe06a:        mov    $0x7000,%esp
0xfe070:        mov    $0xf40ec,%edx
0xfe076:        jmp    0xfc45e
0xfc45e:        mov    %eax,%ecx
0xfc461:        cli
0xfc462:        cld
...
# change to protected mode:

0xfc47f:        mov    %cr0,%eax
0xfc482:        or     $0x1,%eax
0xfc486:        mov    %eax,%cr0
0xfc489:        ljmpl  $0x8,$0xfc491

```

And then, as the tutorial says, the BIOS will load the boot loader from the first sector of the hard disk to the memory.
However, after stepping into the boot loader' instructions, I was rather suprised to find that the CPU was in real mode again:

```
# this is the first instruction of boot loader
[   0:7c00] => 0x7c00:	cli
```

And after some preparations similiar to that in BIOS code, the boot loader changed the CPU to protected mode again:

```
# some preparations
  ...
# change to protected mode again:

  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0
  ljmp    $PROT_MODE_CSEG, $protcseg
```

This truly confused me a lot. It seems that the BIOS changed the CPU from real mode to protected mode, loaded the boot loader into the memory, and changed the CPU back to real mode. And then the boot loader had to agian change the CPU from real mode to protected mode after the control jumped to it.
I guess this can be some history-caused problem, or maybe this design can improve the compatibility of the system.

After changing the CPU to protected mode again, the assembly part of the boot loader( which is *boot.S* ) invoked the function *bootmain*, which load the kernel from the disk into the memory:

```
call bootmain
```

Then after the kernel was loaded, we jump from *bootmain* to the entry of the kernel:

```
((void (*)(void)) (ELFHDR->e_entry))();
```

In the entry part the kernel invoked the page mapping mechanism, since then we can use the virtual address after `0xf0100000`:

```
movl    %cr0, %eax
orl     $(CR0_PE|CR0_PG|CR0_WP), %eax
movl    %eax, %cr0
```

Then after the relocation, we went to the initializatino part of the kernel, and all kinds of functions and services were invoked there. The fantastic story begins here.

```
call    i386_init
```

## 2 Formatted Printing

### 2.1 Validate the Octal Presenting

Before any change was made to the *printfmt.c* file, all octal number in *cprintf* will be presented as `XXX`. After studying the files relative to this issue ( which are *console.c*, *printf.c* and *printfmt.c* ), we know that the problem is in the function *vprintfmt()* in *printfmt.c*.

In *vprintfmt()*, every time we encounter a symbol "%", we will get the next character and jump into a switch structrue to determine what format to be used:

```
while ((ch = *(unsigned char *) fmt++) != '%') {
                        if (ch == '\0')
                                return;
                        putch(ch, putdat);
}

```

And in the switch structrue the code for octal presentation is omitted, so we just need add it:

```
case 'o':
        // Replace this with your code.
        // putch('X', putdat);
        // putch('X', putdat);
        // putch('X', putdat);
        // break;

        // added on May 9th
        putch('0', putdat);
        num = getuint(&ap, lflag);
        base = 8;
        goto number;

```

This means when confronted with an `'%o'`, we know a number should be printed in octal format, so we get the number from the variable list and set the base to `8`, then go to the `number` section to let it print the number for us. Also an octal number should begin with `0`.

### 2.2 Print Sign

It's a piece of cake. Everytime we encounter a `'+'` after a `'%'`, we set a flag to mark that a number must be presented with a sign. After we get a number from the variable list, we specially add a positive sign for it if it's positive. (*The lab text doesn't say what if the number is zero, so I choose to add a positive sign for zero too.*)

```
case '+':
        need_sign = 1;
        goto reswitch;

```

```
if ((long long) num < 0) {
        putch('-', putdat);
        num = -(long long) num;
}
else if(need_sign) {
        putch('+', putdat);
}

```

## 2.4 supporting %n

When confronting symbol `%n`, we get the corresbonding argument frome the `va_list` and use it as the adderss to store the number of the characters printed so far.

```
pchar = va_arg(ap, char*);

```

We will store `*putdat`, which is the very number of current printed characters, to that address. And if the pointer is `nulptr` or the number is overflowed, a warnning message will be printed.

```
if(!pchar) {
        vprintfmt(putch,
                putdat,
                "error! writing through NULL pointer! (%%n argument)\n",
                ap);
}
else if(*((int *)putdat) < 128) {
                *pchar = *((int *)putdat);
}
else {
                *pchar = *((int *)putdat) % 256;
                vprintfmt(putch,
                        putdat,
                        "warning! The value %%n argument pointed to has been overflowed!\n",
                        ap);
}

```

### 2.4 Padding

When `%-` flag is specified, we need to print the number on the left size with correct width. This is how I implement it:

```
        //if the number should be left adjusted
        if(padc == '-') {
                unsigned long long tnum = num;
                unsigned long long power = 1;
                while(tnum) {
                        power *= base;
                        tnum /= base;
                        --width;
                }

                if(!num) {
                        putch('0', putdat);
                        --width;
                }
                while(num) {
                        power /= base;
                        putch("0123456789abcdef"[num / power], putdat);
                        num %= power;
                }
                while(width--)
                        putch(' ', putdat);

                return;
        }

```

First calculate the length of the number and get the remaining width after printing the number, then print the number from high digit to low ones.

## 3 the Stack

### 3.1 Traceback

As the lab text describes, register `%ebp` is pointing to the first address of the stack frame of the current function, which contains the old value of `%ebp` of the last function. Given that, we can trace all the `%ebp` values of the function calling stack like we do in travelling through a link list.
Also, from the calling convention of gcc compiler we know that the return address and the arguments are just on the positions above the address that `%ebp` points to.
So we can implement the trace back function like this:

```
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
        }

```

We get all the `%ebp` values like travalling through a link list. And since the first address of the first stack frame is set to `NULL`, we know we should stop at where `%ebp` equals to `NULL`.

### 3.2 Getting Debugging Information

We want to know the file name, line count, and function name of an instruction at a specified address, and we know these information is stored in the *symbol table* section and *string table* section of the ELF file. We shall find a way to get it.

First fix the function `debug_info` to let it get the right information from the ELF. 
We insert some code to read the name of the file if the correct symbole table is found.

```
        if (lfile == 0)
                return -1;
        // get file name
        if (stabs[lfile].n_strx < stabstr_end - stabstr)
                        info->eip_file = stabstr + stabs[lfile].n_strx;

```

Then we should add the code to search the symbol table of the line count of the specified address, and read the line number if the corresbonding symbol table is found:

```
        stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
        if(lline <= rline) {
                info->eip_line = stabs[lline].n_desc;
        } else {
                return -1;
        }

```

I have read *stab.h* and know the flag for lines' symbol table is `N_LINE`. Also I disassembled the ELF file and know that the line count is stored in member `n_desc` of the `stab` structure.

Then we modify `mon_backtrace` in *monitor.c* to get the corresbonding information and print it.

```
        if(debuginfo_eip((uintptr_t)eip,  &info) >= 0) {
                strcpy(fn_name, info.eip_fn_name);
                fn_name[info.eip_fn_namelen] = '\0';
                cprintf("\t%s:%d %s+%d\n",
                        info.eip_file,
                        info.eip_line,
                        fn_name,
                        eip - info.eip_fn_addr);
}

```

From *kdebug.c* we know that the file name, line count, function name are stored in the member `eip_file`, `eip_line`, `fn_name` of `info` structure respectively.

### 3.3 Buffer Overflow Attack

Ummmmm...Because I'm an exchanging student from USTC and I'm just in my sophomore year, I didn't take that *ICS* course and I have no idea what SJTUers did in that ICS lab. So I have no choice but doing this exercise in my own way...

First we have to invoke function *do_overflow()* using *cprintf()*, this is not hard. We can know the address of the entrance of *do_overflow()* by disassembling the ELF file of the kernel, then we only need to create a proper string with some `%n` specifier in it, and use `cprintf()` to print that string with some arguments pointing to the original return address. By doing so we can change the return address to the entrance of the function `do_overflow()`.
The entrance of `do_overflow()` is here:

```
f010095e <do_overflow>:

```

Then create a string which can write `0xfo10095e` at some address:

```
        for(i = 0; i < 256; i++) {
                str[i] = ' ';
        }
        str[246] = str[98] = str[18] = str[9] = '%';
        str[247] = str[99] = str[19] = str[10] = 'n';
        str[248] = '\0';

```

We get the address of that return address by reading register `%ebp`, and using `cprintf()` to change it:

```
        ebp = read_ebp();
        addr_of_raddr = ebp + 4;

```

```
cprintf(str,
        addr_of_raddr + 1,
        addr_of_raddr + 2,
        addr_of_raddr + 0,
        addr_of_raddr + 3);

```

Now we can jump to function `do_overflow`. But up to now we can't return normally.

I have not found a very elegant way to make it return normally. I insert some assembly code into `start_overflow` to reverve the original return address at the position just above the modified return address( *why not just using pointer operation instead of assembly code...because I don't know what stange optimization gcc will make...* ), so that when `do_overflow` returns, it can get the right return address.
I first use `%ebx` to hold the original return address, for `%ebx` will not change before and after calling a function according to the gcc calling convention:

```
__asm __volatile("mov 4(%ebp), %ebx\n\t");

```

After calling `cprintf()`, I move the entire stack below the return address space for 4 byte using assembly code so that we have a 4 byte space to hold the original return adddress:

```
    __asm __volatile("mov -8(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -12(%ebp)\n\t");
    __asm __volatile("mov -4(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -8(%ebp)\n\t");
    __asm __volatile("mov (%ebp), %eax\n\t");
    __asm __volatile("mov %eax, -4(%ebp)\n\t");
    __asm __volatile("mov 4(%ebp), %eax\n\t");
    __asm __volatile("mov %eax, (%ebp)\n\t");
    # move original return address to the space we leave for it
    __asm __volatile("mov %ebx, 4(%ebp)\n\t");
    __asm __volatile("sub $4, %ebp\n\t");
    __asm __volatile("sub $4, %esp\n\t");


```

As a matter of fact, we don't need the last instruction to sub `%esp`. The essencial reason is that just before the `ret` instrction in `start_overflow`, gcc uses `lea -8(%ebp), esp` to destroy the stack instead of `add $0x100 esp`, so I just need to modify `%ebp` but not `%esp`. However, considering another version or optimization option of compiler which doesn't use this method, I added the last instruction just in case.

Now it returns normally.

# 4 Conclusion

In this lab I gain a relatively full understanding of the booting process and leaned some details of output printing and stack mechanism of the kernel. As a sophomore student I think this lab is a little hard for me...but it truly teaches me a lot.

