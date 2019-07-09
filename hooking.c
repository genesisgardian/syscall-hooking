#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

//declare module info
MODULE_DESCRIPTION("Hooking syscall");
MODULE_AUTHOR("genesis(Che-Hao Liu) <genesisgardian at="" gmail.com="">");
MODULE_LICENSE("GPL");

unsigned long *sys_call_table;
extern asmlinkage ssize_t my_stub_execve_hook(char*, char**, char**);
asmlinkage ssize_t (*o_execve)(const char* filename, char* const argv[], char* const envp[]);

// custom execve for hook
asmlinkage ssize_t my_execve(const char* filename, char* const argv[], char* const envp[])
{
	int retval;
	printk("In my execve\n");

	retval = (*o_execve)(filename, argv, envp);
	printk("retval: %d\n", retval);
	return 0;
}

unsigned long* find_sys_call_table(void)
{
	unsigned long **sctable, rodata_start_addr, rodata_end_addr, _etext_addr;

    _etext_addr = kallsyms_lookup_name("_etext");
    rodata_start_addr = ALIGN(_etext_addr, HPAGE_SIZE);
    rodata_end_addr = ALIGN(rodata_start_addr + 1, HPAGE_SIZE);
	
	for(sctable = (unsigned long**) rodata_start_addr ; sctable < (unsigned long**) rodata_end_addr ; ++sctable) {
		if(sctable[__NR_close] == (unsigned long*)sys_close) // compare syscall close
			return (unsigned long*)&sctable[0];
	}
	
	return 0;
}

int hooking_init(void)
{	
	// find system call table
	sys_call_table = find_sys_call_table();
	if (!sys_call_table) {
		printk("Could not find sys_call_table.\n");
		return 0;
	}

	printk("Find sys_call_table: %lx\n", (unsigned long)sys_call_table);

	// turnoff WP in cr0, and replace sys_execve()
	write_cr0(read_cr0() & (~0x10000));
	o_execve = (void*)xchg(&sys_call_table[__NR_execve], (unsigned long)my_stub_execve_hook);

	// turnon WP
	write_cr0(read_cr0() | 0x10000);

	printk("Hook execve done.\n");
	
	return 0;

}

void hooking_exit(void)
{
	// turnoff WP in cr0, and restore sys_execve()
	write_cr0(read_cr0() & (~0x10000));
	xchg(&sys_call_table[__NR_execve], (unsigned long)o_execve);

	// turnon WP
	write_cr0(read_cr0() | 0x10000);

	printk("Restore execve done.\n");	

}

module_init(hooking_init);
module_exit(hooking_exit);

