/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

struct bitmap *swap_table;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
 	size_t st_size = (disk_size(swap_disk)*DISK_SECTOR_SIZE)>>12;
 	swap_table = bitmap_create(st_size);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	/*added */
	size_t temp = anon_page->so_index;
	if(bitmap_test(swap_table, temp)){
		for(int i = 0; i < 8; i++){
			disk_read(swap_disk, temp*8 + i, kva + DISK_SECTOR_SIZE*i);
		}
		anon_page->so_index = NULL;
		bitmap_set(swap_table, temp, false);
		return true;
	}
	else return false;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	/* added */
	size_t temp = bitmap_scan(swap_table, 0, 1, false);
	if(temp == BITMAP_ERROR){
		PANIC("No free slots in disk");
	}
	// PGSIZE == 2^12, DISK_SECTOR_SIZE == 2^9
	for(int i = 0; i < 8; i++){
		disk_write(swap_disk, temp*8 + i, page->frame->kva + DISK_SECTOR_SIZE*i);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	anon_page->so_index = temp;
	bitmap_set(swap_table, temp, true);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
