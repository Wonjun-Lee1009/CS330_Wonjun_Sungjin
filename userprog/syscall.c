#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
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

void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
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

struct lock file_sys_lock;

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
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	char *rsptr = f->rsp;
	if(!is_user_vaddr(rsptr)) exit(-1);
	// PANIC("%d %d %d %d\n\n", f->rsp, f->R.rax, f->R.rsi, f->R.rdx);
	switch(f->R.rax){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			exit((int)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_FORK:
			f->R.rax = fork(rsptr+8);
			break;
		case SYS_EXEC:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = exec((const char *)(rsptr+8));
			break;
		case SYS_WAIT:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = wait((tid_t)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_CREATE:
			// if (!is_user_vaddr((rsptr+32))) exit(-1);
			// if (!is_user_vaddr((rsptr+40))) exit(-1);
			f->R.rax = create((const char *)*(uintptr_t *)(rsptr+32),(unsigned)*(uintptr_t *)(rsptr+40));
			break;
		case SYS_REMOVE:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = remove((const char *)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_OPEN:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = open((const char *)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_FILESIZE:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = filesize((int)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_READ:
			// if (!is_user_vaddr((rsptr+40))) exit(-1);
			f->R.rax = read((int)*(uintptr_t *)(rsptr+40), (void *)*(uintptr_t *)(rsptr+48), (unsigned *)*(uintptr_t *)(rsptr+56));
			break;
		case SYS_WRITE:
			// if (!is_user_vaddr((rsptr+40))) exit(-1);
			// if (!is_user_vaddr((rsptr+48))) exit(-1);
			// if (!is_user_vaddr((rsptr+56))) exit(-1);
			// PANIC("fuck! %d %d %d\n", f->R.rdi, f->R.rsi, f->R.rdx);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			// if (!is_user_vaddr((rsptr+32))) exit(-1);
			// if (!is_user_vaddr((rsptr+40))) exit(-1);
			seek((int)*(uintptr_t *)(rsptr+32), (unsigned)*(uintptr_t *)(rsptr+40));
			break;
		case SYS_TELL:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			f->R.rax = tell((int)*(uintptr_t *)(rsptr+8));
			break;
		case SYS_CLOSE:
			// if (!is_user_vaddr((rsptr+8))) exit(-1);
			close((int)*(uintptr_t *)(rsptr+8));
			break;
		default:
			thread_exit ();
	}
	// printf ("system call!\n");
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
fork (const char *thread_name){
	tid_t child_pid;
	struct thread *curr;
	struct intr_frame *user_tf;
	
	curr = thread_current();
	user_tf = &(curr->f_tf);
	child_pid = process_fork(curr, user_tf);
	sema_down(&get_child_process(child_pid)->sema_load);
	return child_pid;
}

int
exec (const char *cmd_line){
	char *cmd_copy;
    cmd_copy = palloc_get_page(0);
    memcpy(cmd_copy, cmd_line, strlen(cmd_line));
	return process_exec(cmd_line);
}

int
wait (tid_t pid){
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size){
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	return filesys_create(file, initial_size);
}

bool
remove (const char *file){
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	return filesys_remove(file);
}

int
open (const char *file){
	struct thread *curr;
	struct file *opened_file;
	int ret;

	curr = thread_current();
	if(!is_user_vaddr(file) || file == NULL) exit(-1);
	lock_acquire(&file_sys_lock);
	opened_file = filesys_open(file);
	if(opened_file == NULL){
		ret = -1;
	}
	else{
		ret = 3;
		while(curr->fl_descr[ret] != NULL) ret++;
		if (strcmp(curr->name, file) == 0) file_deny_write(opened_file);
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
			exit(-1);
		}
		ret = file_read(curr->fl_descr[fd], buffer, size);
	}
	lock_release(&file_sys_lock);
	return ret;
}

int
write (int fd, const void *buffer, unsigned size){
	int ret = -1;

	PANIC("%d\n", fd);
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
		file_deny_write(curr_file);
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

	if(curr_file == NULL) exit(-1);
	curr_file = NULL;
	file_close(curr_file);
}
