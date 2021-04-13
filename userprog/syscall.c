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
pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);
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

	uintptr_t *rsptr = f->rsp;
	switch(*rsptr){
		case SYS_HALT:
		case SYS_EXIT:
		case SYS_FORK:
		case SYS_EXEC:
		case SYS_WAIT:
		case SYS_CREATE:
		case SYS_REMOVE:
		case SYS_OPEN:
		case SYS_FILESIZE:
		case SYS_READ:
		case SYS_WRITE:
		case SYS_SEEK:
		case SYS_TELL:
		case SYS_CLOSE:
	}
	printf ("system call!\n");
	thread_exit ();
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
}

pid_t
fork (const char *thread_name){

}

int
exec (const char *cmd_line){
	return process_exec(cmd_line);
}

int
wait (pid_t pid){
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size){
	if(!is_user_vaddr(file)) exit(-1);
	return filesys_create(file, initial_size);
}

bool
remove (const char *file){
	if(!is_user_vaddr(file)) exit(-1);
	return filesys_remove(file);
}

int
open (const char *file){

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
		while(((char *)buffer)+ret==NULL) ret++;
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
	if(fd == 1){
		putbuf(buffer, size);
		ret = length;
	}
	else if(fd>2){
		struct thread *curr = thread_current();
		struct file *curr_file = curr->fl_descr[fd];
		if(curr_file == NULL){
			lock_release(&file_sys_lock);
			exit(-1);
		}
		if(curr_file->deny_write == true) file_deny_write(curr_file);
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
