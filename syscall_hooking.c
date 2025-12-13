#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LavaTime");
MODULE_DESCRIPTION("A syscall hooking module");

static unsigned long sym_addr = 0;

module_param(sym_addr, ulong, 0644);

static int __init syscall_hooking_init(void)
{
	if (sym_addr == 0)
	{
		printk(KERN_WARNING "Syscall_hooker: Didn't receive a sys_call_table location!\n");
		return -1;
	}
	void **sys_call_table = (void **)sym_addr;
	
	printk(KERN_INFO "Syscall_hooker: Target acquired. Address: <REDACTED>\n");
	
	return 0;
}

static void __exit syscall_hooking_exit(void)
{
	printk(KERN_INFO "Syscall_hooker: Mission complete");
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_exit);

