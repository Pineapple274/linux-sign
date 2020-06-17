#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>

char *license="Thank you for using this system!\n-------------------------------\n-                             -\n-                             -\n-          MicroLock          -\n-                             -\n-                             -\n-------------------------------\n";
char b[256];


static int handler_pre(struct kprobe *p, struct pt_regs *regs){   
    char *envp[]={NULL};
    char *sign_check = "/home/name/Desktop/Lock/signcheck";
    char *file_path = dentry_path_raw((((struct linux_binprm *)regs->di)->file)->f_path.dentry,b,256);
    
    
    char *argv[]={sign_check,file_path,NULL};
    int ret=call_usermodehelper(sign_check,argv,envp,UMH_WAIT_PROC);

    printk("%s\n",license);
    printk("ret : %d\n",ret);
    printk("present file is : %s\n",file_path); 
	return 0;
}


static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    return;
}


static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= "load_elf_binary",
};
 
static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;
 
	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
	return 0;
}
 
static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}
 
module_init(kprobe_init)
module_exit(kprobe_exit)

MODULE_LICENSE("GPL");

MODULE_AUTHOR("Jian");