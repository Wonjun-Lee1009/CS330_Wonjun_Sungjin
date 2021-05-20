#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "kernel/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_RW_address(struct intr_frame *f, int type);
bool check_MMAP_address(struct intr_frame *);

void halt (void);
void exit (int status);
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void *mmap(struct intr_frame *f);
void munmap(void *addr);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// struct lock file_sys_lock;

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&file_sys_lock);
	// PANIC("fuck");
	// intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	// PANIC("fuck");
}

enum read_or_write{
	READ, WRITE
};

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	char *rsptr = f->rsp;
#ifdef VM
	thread_current()->stptr = f->rsp;
#endif
	if(!is_user_vaddr(rsptr)) exit(-1);
	// PANIC("%d %d %d %d\n\n", f->rsp, f->R.rax, f->R.rsi, f->R.rdx);
	switch(f->R.rax){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			// PANIC("fork checking!!: %d\n", f->rsp);
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (!is_user_vaddr(f->R.rdi)) thread_exit();
			f->R.rax = exec((const char *)f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_RW_address(f, READ);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_RW_address(f, WRITE);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_MMAP:
			if(check_MMAP_address(f)) f->R.rax = mmap(f);
			else f->R.rax = NULL;
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		default:
			thread_exit ();
	}
	// printf ("system call!\n");
}

void
check_RW_address(struct intr_frame *f, int type){
	void *buf = f->R.rsi;
	unsigned size = f->R.rdx;
	int i;

	for(i = 0; i<size; i++){
		if(is_kernel_vaddr(buf + i)) exit(-1);
		struct page *page = spt_find_page(&thread_current()->spt, buf + i);
		if(!page) exit(-1);
		if(type == WRITE) return;
		else if(page->writable == READ) exit(-1);
	}
}

bool
check_MMAP_address(struct intr_frame *f){
	if(is_kernel_vaddr(f->R.rdi) || f->R.rdi == NULL) return false;
	if(spt_find_page(&thread_current()->spt, f->R.rdi)) return false;
	if(f->R.rsi <= 0) return false;
	if(pg_ofs(f->R.r8)!=0) return false;
	if(f->R.rdi +f->R.rsi ==0) return false;
	if(f->R.r10 == 0 || f->R.r10 == 1) exit(-1);
}

void
halt(void){
	power_off();
}

void
exit(int status){
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	for (int i = 3; i < 128; i++){
		if (thread_current()->fl_descr[i] != NULL) close(i);
	}
	thread_exit();
}

tid_t
fork (const char *thread_name, struct intr_frame *f){
	tid_t child_pid;
	struct thread *curr;
	struct thread *child_th;
	// struct intr_frame *user_tf;
	
	// curr = thread_current();
	// user_tf = &(curr->tf);
	// PANIC("current f_tf, tf: %d %d\n", curr->f_tf.rsp, curr->tf.rsp);
	child_pid = process_fork(thread_name, f);
	// child_th = get_child_process(child_pid);
	// sema_down(&child_th->sema_load);
	return child_pid;
}

int
exec (const char *cmd_line){
	char *cmd_copy;
    cmd_copy = palloc_get_page(PAL_ZERO);
    memcpy(cmd_copy, cmd_line, strlen(cmd_line));
	return process_exec(cmd_copy);
}

int
wait (tid_t pid){
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size){
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	// if(pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	return filesys_create(file, initial_size);
}

bool
remove (const char *file){
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	// if(pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	return filesys_remove(file);
}

int
open (const char *file){
	struct thread *curr;
	struct file *opened_file;
	int ret;

	curr = thread_current();
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	// if(pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	lock_acquire(&file_sys_lock);
	opened_file = filesys_open(file);
	if(opened_file == NULL){
		ret = -1;
	}
	else{
		ret = 3;
		while(curr->fl_descr[ret] != NULL) ret++;
		if (strcmp(thread_name(), file) == 0) file_deny_write(opened_file);
		curr->fl_descr[ret] = opened_file;
	}
	lock_release(&file_sys_lock);
	return ret;
}

int
filesize (int fd){
	struct thread *curr = thread_current();
	struct file *curr_file = curr->fl_descr[fd];

	if(curr_file == NULL) exit(-1);
	return file_length(curr_file);
}

int
read (int fd, void *buffer, unsigned size){
	int ret;
	
	if(!is_user_vaddr(buffer)) exit(-1);
	lock_acquire(&file_sys_lock);

	if(fd == 0){
		while(((char *)buffer)+ret == NULL) ret++;
	}
	else if(fd>2){
		struct thread *curr = thread_current();
		if(curr->fl_descr[fd] == NULL){
			// PANIC("fd : %d\n", fd);
			ret = -1;
		}
		else ret = file_read(curr->fl_descr[fd], buffer, size);
	}
	lock_release(&file_sys_lock);
	return ret;
}

int
write (int fd, const void *buffer, unsigned size){
	int ret = -1;

	if(!is_user_vaddr(buffer)) exit(-1);
	lock_acquire(&file_sys_lock);

	if(fd == 1){
		putbuf(buffer, size);
		ret = size;
	}
	else if(fd>2){
		struct thread *curr = thread_current();
		struct file *curr_file = curr->fl_descr[fd];
		if(curr_file == NULL){
			lock_release(&file_sys_lock);
			exit(-1);
		}
		// file_deny_write(curr_file);
		ret = file_write(curr_file, buffer, size);
	}
	lock_release(&file_sys_lock);
	return ret;
}

void
seek (int fd, unsigned position){
	struct thread *curr = thread_current();
	struct file *curr_file = curr->fl_descr[fd];

	if(curr_file == NULL) exit(-1);
	return file_seek(curr_file, position);
}

unsigned
tell (int fd){
	struct thread *curr = thread_current();
	struct file *curr_file = curr->fl_descr[fd];

	if(curr_file == NULL) exit(-1);
	return file_tell(curr_file);
}

void
close (int fd){
	struct thread *curr = thread_current();
	struct file *curr_file = curr->fl_descr[fd];

	// if(pml4_get_page(thread_current()->pml4, curr_file) == NULL) exit(-1);
	if(curr_file == NULL) exit(-1);
	curr->fl_descr[fd] = NULL;
	file_close(curr_file);
}

void *mmap(struct intr_frame *f){
	struct file *file;

	if((file = thread_current()->fl_descr[f->R.r10]) == NULL) return NULL;

	return do_mmap(f->R.rdi, f->R.rsi, f->R.rdx, file, f->R.r8);
}

void munmap(void *addr){
	do_munmap(addr);
}