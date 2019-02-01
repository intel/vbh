#define assert(p) do {	\
    if (!(p)){			\
        printk(KERN_CRIT "Assert at %s:%d assert(%s)\n",    \
                __FILE__, __LINE__, #p);                    \
            BUG();  \
    }               \
}while(0)


void asm_make_vmcall(unsigned int hypercall_id, void *params);
