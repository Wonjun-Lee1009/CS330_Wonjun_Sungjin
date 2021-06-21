#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format){
		do_format ();
	}

	fat_open ();
	thread_current()->curr_dir = dir_open_root();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	#ifdef EFILESYS
	cluster_t inode_cluster = fat_create_chain(0);
	disk_sector_t inode_sector = inode_cluster;
	char file[FILE_LEN_MAX +1];
	struct dir *dir = path_to_file(name, file);
	// struct dir *dir = dir_open_root();
	bool success = (dir != NULL
			&& inode_cluster
			&& inode_create (inode_sector, initial_size, FILE)
			&& dir_add (dir, file, inode_sector));

	if (!success && inode_cluster != 0)
        fat_remove_chain(inode_cluster, 0);
	
	dir_close(dir);
	return success;
	#else
	disk_sector_t inode_sector = 0;
	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
	dir_close (dir);

	return success;

	#endif
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	#ifdef EFILESYS
	char file[NAME_MAX+1];
	struct dir *dir;
	struct inode *inode;

	dir = path_to_file(name, file);
	// PANIC("%s\n", file);
	inode = NULL;
	if(dir!=NULL){
		dir_lookup(dir, file, &inode);
		if(!inode || !inode->data.is_sym){ // if there's no file or it is not a link file
			dir_close(dir);
			return file_open(inode);
		}
		else{
			while(true){
				dir_close(dir);
				name = inode->data.link;
				dir = path_to_file(name, file);
				if(dir == NULL) break;
				dir_lookup(dir, file, &inode);
				if(inode == NULL) break;
			}
		}
	}
	dir_close(dir);
	return file_open(inode);

	#else
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
	#endif
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	#ifdef EFILESYS
	char file[NAME_MAX+1];
	char name_tmp[NAME_MAX+1];
	struct dir *dir, *dir_opened;
	struct inode *inode;
	bool success;

	if(!strcmp(name, "/")) return false;

	dir = path_to_file(name, file);
	inode = NULL;
	if(dir == NULL){
		// dir_close(dir);
		success = false;
	}
	else{
		dir_lookup(dir, file, &inode);
		if(!inode_is_dir(inode)){ //file
			inode_close(inode);
			if(dir && dir_remove(dir, file)) success = true;
			// dir_close(dir);
		}
		else{ //directory
			dir_opened = dir_open(inode);
			dir_opened->pos = 2*(sizeof(struct dir_entry));
			if(dir_readdir(dir_opened, name_tmp)){
				if(dir && dir_remove(dir_opened, file))
					success = true;
				else
					success = false;
			}
			else{
				struct dir *curr_dir = thread_current()->curr_dir;
				disk_sector_t curr_dir_location, opened_dir_location;
				curr_dir_location = inode_get_inumber(dir_get_inode(curr_dir));
				opened_dir_location = inode_get_inumber(dir_get_inode(dir_opened));
				if(curr_dir_location != opened_dir_location){
					if(dir && dir_remove(dir, file))
						success = true;
					else
						success = false;
				}
			}
			dir_close(dir_opened);
		}
	}
	dir_close(dir);
	return success;

	#else
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);
	
	return success;
	#endif
}

bool filesys_chdir(const char *name){
	bool ret = false;
	char file[NAME_MAX+1];
	struct inode *inode = NULL;
	struct dir *dir = path_to_file(name, file);
	
	if(dir){
		if(dir_lookup(dir, file, &inode)){
			struct dir *chdir = dir_open(inode);
			dir_close(thread_current()->curr_dir);
			thread_current()->curr_dir = chdir;
			ret = true;	
		}
	}
	dir_close(dir);
	return ret;
}

bool filesys_mkdir(const char *name){
	char file[FILE_LEN_MAX +1];
	bool success = false;

	struct dir *dir = path_to_file(name, file);
	struct dir *dir_named_file;
	struct inode *inode_for_dir_named_file;
	cluster_t clst = fat_create_chain(0);
	
	success = (dir != NULL
			&& clst
			&& dir_create (clst, 16)
			&& dir_add (dir, file, clst));

	if(success){
		dir_lookup(dir, file, &inode_for_dir_named_file);
		dir_named_file = dir_open(inode_for_dir_named_file);
		struct inode * tmp = dir_get_inode(dir);
		dir_add(dir_named_file, ".", clst);
		dir_add(dir_named_file, "..", inode_get_inumber(tmp));
		dir_close(dir_named_file);
		// dir_close(dir);
	}

	if (!success && clst != 0)
		fat_remove_chain(clst, 0);

	dir_close(dir);
	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();

	if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");

	struct dir *dir = dir_open_root();
	dir_add(dir, ".", ROOT_DIR_SECTOR);
	dir_add(dir, "..", ROOT_DIR_SECTOR);
	dir_close(dir);
	fat_close ();
	
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

struct dir *
path_to_file(char *path, char *file){
	struct dir *dir = NULL;
	char path_cpy[FILE_LEN_MAX+1];

	if(path == NULL || file == NULL || strlen(path) == 0) return NULL;
	strlcpy(path_cpy, path, FILE_LEN_MAX+1);

	if(path_cpy[0] == '/') dir = dir_open_root();
	else if(thread_current()->curr_dir == NULL) dir = dir_open_root();
	else dir = dir_reopen(thread_current()->curr_dir);
	
	char *token, *token_next, *token_save;
	token = strtok_r(path_cpy, "/", &token_save);
	token_next = strtok_r(NULL, "/", &token_save);

	if(token == NULL){
		strlcpy(file, ".", 2);
		return dir;
	}

	while(token != NULL && token_next != NULL){
		struct inode *inode_tmp;

		if(!dir_lookup(dir, token, &inode_tmp)){
			dir_close(dir);
			return NULL;
		}

		if(!inode_tmp->data.is_sym){
			if(!inode_is_dir(inode_tmp)){
				dir_close(dir);
				inode_close(inode_tmp);
				return NULL;
			}
			dir_close(dir);
			dir = dir_open(inode_tmp);
			token = token_next;
			token_next = strtok_r(NULL, "/", &token_save);
		}
		else{
			char link_cpy[FILE_LEN_MAX+1];
			strlcpy(link_cpy, inode_tmp->data.link, FILE_LEN_MAX+1);
			strlcpy(path_cpy, link_cpy, strlen(link_cpy) + 1);

			strlcat(path_cpy, "/", strlen(path_cpy) + 2);
			strlcat(path_cpy, token_next, strlen(path_cpy) + strlen(token_next) + 1);
			strlcat(path_cpy, token_save, strlen(path_cpy) + strlen(token_save) + 1);

			dir_close(dir);

			if(path_cpy[0] == '/') dir = dir_open_root();
			else if(thread_current()->curr_dir == NULL) dir = dir_open_root();
			else dir = dir_reopen(thread_current()->curr_dir);

			token = strtok_r(path_cpy, "/", &token_save);
			token_next = strtok_r(NULL, "/", &token_save);
		}
	}
	strlcpy(file, token, strlen(token)+1);
	return dir;
}