#define orig_ax orig_eax
#define reg_ax  eax
#define reg_ip  eip

#define syscall_arg0 ebx
#define syscall_arg1 ecx
#define syscall_arg2 edx
#define syscall_arg3 esi
#define syscall_arg4 edi
#define syscall_arg5 ebp

#define mmap_syscall __NR_mmap2
