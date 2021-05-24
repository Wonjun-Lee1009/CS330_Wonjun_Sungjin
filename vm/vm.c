/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
 #include <hash.h>
 #include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
struct list frame_table;

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *p = (struct page *) malloc(sizeof(struct page));
 		bool (*initializer)(struct page *, enum vm_type, void *kva);
 		if(VM_TYPE(type) == VM_ANON){
 			initializer = anon_initializer;
 		}
 		else if(VM_TYPE(type) == VM_FILE){
 			initializer = file_backed_initializer;
 		}

 		uninit_new(p, upage, init, type, aux, initializer);
 		p->writable = writable;
 		p->vm_type = type;
		
		/* TODO: Insert the page into the spt. */
		bool succ = spt_insert_page(spt, p);
 		return succ;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page *p = (struct page*)malloc(sizeof(struct page));
 	struct hash_elem *e;
	
	p->va = pg_round_down(va);
 	e = hash_find(&spt->hash_table, &p->spt_elem);
	free(p);
 	if(e != NULL) page = hash_entry(e, struct page, spt_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if(hash_insert(&spt->hash_table, &page->spt_elem) == NULL) succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	struct list_elem *elem_needle, *temp_elem;
	for(elem_needle = list_begin(&frame_table);
		elem_needle != list_end(&frame_table); ){
			victim = list_entry(elem_needle, struct frame, ft_elem);
			if(pml4_is_accessed(thread_current()->pml4, victim->page->va)){
				elem_needle = list_next(elem_needle);
				pml4_set_accessed(thread_current()->pml4, victim->page->va, 0);
			}
			else return victim;
	}

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = (struct frame *)malloc(sizeof(struct frame));
	void *p = palloc_get_page(PAL_USER);
	frame->kva = p;
 	if(p == NULL) return vm_evict_frame();

 	frame->page = NULL;
	 list_push_back(&frame_table, &frame->ft_elem);
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	while(vm_alloc_page(VM_MARKER_0 | VM_ANON, addr, 1)){
		vm_claim_page(addr);
		addr += PGSIZE;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(is_kernel_vaddr(addr)) return false;

	void *rsp_stack = thread_current()->stptr;
	if(!is_kernel_vaddr(f->rsp)){
		rsp_stack = f->rsp;
	}

	page = spt_find_page(spt, addr);

	if(not_present){
		if(page == NULL){
			if(USER_STACK - (1<<20) <= addr && addr <= USER_STACK)
            {
				if(rsp_stack == addr + 8 || addr > rsp_stack){
					vm_stack_growth(pg_round_down(addr));
                	return true;
				}
            }
            return false;
		}
		else{
			if((!(page->writable)) && write){
				return false;
			}
			return vm_do_claim_page(page);
		}
	}
    else return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
 	if(page == NULL) return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	bool wr = page->writable;
 	void* succ1 = pml4_get_page(thread_current()->pml4, page->va);
 	bool succ2 = pml4_set_page(thread_current()->pml4, page->va, frame->kva, wr);
	// printf("%x\t%d\n", page->va, page->operations->type);
	if((succ1 == NULL) && succ2) return swap_in (page, frame->kva);
 	else return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;

 	hash_first (&i, &src->hash_table);
 	while (hash_next (&i))
 	{
        struct page *src_page = hash_entry (hash_cur (&i), struct page, spt_elem);

		enum vm_type type = page_get_type(src_page);
		void *p_va = src_page->va;
		bool writable = src_page->writable;

		if(src_page->operations->type == VM_UNINIT)
		{
			vm_initializer *init = src_page->uninit.init;
			void* aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(type, p_va, writable, init, aux);
		}

		else
		{
			vm_alloc_page(type, p_va, writable);
			vm_claim_page(p_va);
			struct page* dst_page = spt_find_page(dst, p_va);
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
 	}
 	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(hash_empty(&spt->hash_table)) return;
	struct hash_iterator i;
	hash_first (&i, &spt->hash_table);
	while (hash_next (&i))
	{
		struct page *page = hash_entry (hash_cur (&i), struct page, spt_elem);
		destroy(page);
	}
}
