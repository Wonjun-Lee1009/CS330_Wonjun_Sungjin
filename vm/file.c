/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
bool lazy_mmap(struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
	/* added */
	// struct carrier *rec = (struct carrier *)page->uninit.aux;
 	struct file *file = file_page->file;
	off_t pos = file_page->pos;
 	size_t page_read_bytes = file_page->prd;
 	size_t page_zero_bytes = file_page->pzd;
	if (file_read_at (file, page->frame->kva, page_read_bytes, pos) != (int) page_read_bytes) {
 		return false;
 	}
 	memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);
 	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
	/* added */
	// struct carrier *rec = (struct carrier *)page->uninit.aux;
 	struct file *file = file_page->file;
	off_t pos = file_page->pos;
 	size_t page_read_bytes = file_page->prd;
 	size_t page_zero_bytes = file_page->pzd;
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
 		file_write_at(file, page->va, page_read_bytes, pos);
		pml4_set_dirty(thread_current()->pml4, page->va, false);
 	}
 	pml4_clear_page(thread_current()->pml4, page->va);
 	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	void *addr_original = addr;
	struct file *refile = file_reopen(file);
    size_t read_bytes = length;
	if(read_bytes>file_length(refile)) read_bytes = file_length(refile);
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
	// printf("len : %x\n", read_bytes);
	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct carrier *aux = (struct carrier *)malloc(sizeof(struct carrier));
		aux->file = refile;
 		aux->pos = offset;
 		aux->prd = page_read_bytes;
 		aux->pzd = page_zero_bytes;
 		offset += page_read_bytes;


		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, lazy_mmap, aux))
			return false;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
	}
	return addr_original;
}

bool
lazy_mmap (struct page *page, void *aux) {
	struct carrier *rec = (struct carrier*)aux;
 	struct file *file = rec->file;
	 off_t ori_pos = file_tell(file);
	off_t pos = rec->pos;
 	size_t page_read_bytes = rec->prd;
 	size_t page_zero_bytes = rec->pzd;
	 struct file_page *file_page = &page->file;
	 file_page->file = rec->file;
	 file_page->pos = rec->pos;
	 file_page->prd = rec->prd;
	 file_page->pzd = rec->pzd;
	if (file_read_at (file, page->frame->kva, page_read_bytes, pos) != (int) page_read_bytes) {
 		palloc_free_page(page->frame->kva);
 		return false;
 	}
 	memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);
	 file_seek(file, ori_pos);
 	return true;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct page *page;
	struct carrier * aux;
	//PANIC("shitt\n");
	for(page = spt_find_page(&thread_current()->spt, addr);
		 page!=NULL;
		 page = spt_find_page(&thread_current()->spt, addr)){
		//  printf("%x\n", addr);
		// aux = (struct carrier *)page->uninit.aux;
		struct file_page *file_page = &page->file;
		struct file *file = file_page->file;
		off_t pos = file_page->pos;
		size_t page_read_bytes = file_page->prd;
		size_t page_zero_bytes = file_page->pzd;
		if(pml4_is_dirty(thread_current()->pml4, page->va)){
			//printf("%x\n", page->va);
			file_write_at(file, addr, page_read_bytes, pos);
			pml4_set_dirty(thread_current()->pml4, page->va, false);
		}
		pml4_clear_page(thread_current()->pml4, page->va);
		addr+=PGSIZE;
	}
	// PANIC("shit\n");
}
