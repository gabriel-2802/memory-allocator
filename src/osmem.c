// SPDX-License-Identifier: BSD-3-Clause
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "../tests/snippets/test-utils.h"
#include "../utils/block_meta.h"
#include "../utils/osmem.h"


#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_DATA_ALIGNMENT ALIGN(sizeof(block_meta_t))
#define PREALLOC_SIZE (128 * 1024)
#define MINIMUM_BLOCK_SIZE (META_DATA_ALIGNMENT + 8)

typedef struct block_meta block_meta_t;

block_meta_t *my_heap_list;

block_meta_t *my_mmap_list;


int minimum(int a, int b)
{
	return a < b ? a : b;
}

block_meta_t *get_last_block(block_meta_t *head)
{
	block_meta_t *current = head;

	while (current->next)
		current = current->next;
	return current;
}

void add_block_last_to_list(block_meta_t *head, block_meta_t *block)
{
	block_meta_t *last = get_last_block(head);

	last->next = block;
	block->prev = last;
	block->next = NULL;
}

void try_split_block(block_meta_t *block, size_t size)
{
	if (block->size - size < MINIMUM_BLOCK_SIZE)
		return;

	block_meta_t *new_free_block = (block_meta_t *)((char *)(block + 1) + size);

	new_free_block->size = block->size - size - META_DATA_ALIGNMENT;
	new_free_block->status = STATUS_FREE;

	//updatam size ul current block ului
	block->size = size;

	if (block->next)
		block->next->prev = new_free_block;

	new_free_block->next = block->next;
	block->next = new_free_block;
	new_free_block->prev = block;
}

void try_merge_blocks(void)
{
	block_meta_t *current = my_heap_list;

	while (current) {
		if (current->status == STATUS_FREE && current->next && current->next->status == STATUS_FREE) {
			current->size += current->next->size + META_DATA_ALIGNMENT;
			current->next = current->next->next;

			if (current->next)
				current->next->prev = current;
		}
		current = current->next;
	}
}

block_meta_t *find_best_free_block(size_t size)
{
	block_meta_t *current = my_heap_list;
	block_meta_t *best = NULL;

	while (current) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (best == NULL || current->size < best->size)
				best = current;
		}
		current = current->next;
	}

	return best;
}

/* functia initializeaza heap-ul */
void init_heap(void)
{
	my_heap_list = sbrk(0);
	sbrk(PREALLOC_SIZE);
	my_heap_list->size = PREALLOC_SIZE - META_DATA_ALIGNMENT;
	my_heap_list->next = NULL;
	my_heap_list->prev = NULL;
	my_heap_list->status = STATUS_FREE;
}

void *os_malloc_calloc(size_t size, size_t limit, int calloc)
{
	if (size <= 0)
		return NULL;

	size_t block_size = ALIGN(size) + META_DATA_ALIGNMENT;
	block_meta_t *block_ptr = NULL;

	if ((size_t)block_size < limit) {
		if (!my_heap_list)
			init_heap();

		block_ptr = find_best_free_block(ALIGN(size));
		if (!block_ptr) {
			block_ptr = get_last_block(my_heap_list);
			if (block_ptr->status == STATUS_FREE) {
				sbrk(ALIGN(size) - block_ptr->size);
				block_ptr->size = ALIGN(size);
				block_ptr->status = STATUS_ALLOC;
			} else {
				block_ptr = sbrk(0);
				sbrk(block_size);
				block_ptr->size = ALIGN(size);
				block_ptr->status = STATUS_ALLOC;
				add_block_last_to_list(my_heap_list, block_ptr);
			}
		} else {
			block_ptr->status = STATUS_ALLOC;
			try_split_block(block_ptr, ALIGN(size));
		}
	} else {
		if (!my_mmap_list) {
			my_mmap_list = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			block_ptr = my_mmap_list;
			block_ptr->size = ALIGN(size);
			block_ptr->status = STATUS_MAPPED;
			block_ptr->next = NULL;
			block_ptr->prev = NULL;
		} else {
			block_ptr = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			block_ptr->size = ALIGN(size);
			block_ptr->status = STATUS_MAPPED;
			add_block_last_to_list(my_mmap_list, block_ptr);
		}
	}
	if (calloc)
		memset(block_ptr + 1, 0, size);
	return block_ptr + 1;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc*/
	return os_malloc_calloc(size, MMAP_THRESHOLD, 0);
}
void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;

	block_meta_t *block = (block_meta_t *)ptr - 1;

	if (block->status == STATUS_FREE)
		return;

	if (block->status == STATUS_MAPPED) {
		if (block->prev)
			block->prev->next = block->next;

		if (block->next)
			block->next->prev = block->prev;

		if (block->next == NULL && block->prev == NULL)
			my_mmap_list = NULL;

		munmap(block, block->size + META_DATA_ALIGNMENT);
	} else {
		block->status = STATUS_FREE;
		// nu vor exista 2 block uri free consecutive
		try_merge_blocks();
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t limit = (size_t)getpagesize();

	return os_malloc_calloc(nmemb * size, limit, 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (!size) {
		os_free(ptr);
		return NULL;
	}

	if (!ptr)
		return os_malloc_calloc(size, MMAP_THRESHOLD, 0);

	block_meta_t *block = (block_meta_t *)ptr - 1;

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);

		memcpy(new_ptr, ptr, minimum(block->size, size));
		os_free(ptr);
		return new_ptr;
	}

	void *new_ptr = NULL;

	if (block->status == STATUS_ALLOC) {
		if (block->size >=  ALIGN(size)) {
			try_split_block(block,  ALIGN(size));
			return ptr;
		}

		//else
		if (block->next && block->next->status == STATUS_FREE) {
			block->size += block->next->size + META_DATA_ALIGNMENT;
			block_meta_t *next_next = block->next->next;

			block->next = next_next;
			if (next_next)
				next_next->prev = block;

			if (block->size >=  ALIGN(size)) {
				try_split_block(block,  ALIGN(size));
				return ptr;
			}
		}

		if (block->next == NULL) {
			sbrk(ALIGN(size) - block->size);
			block->size = ALIGN(size);
			return ptr;
		}

		//daca am ajuns aici, trebuie sa alocam un nou bloc
		new_ptr = os_malloc(size);
		if (new_ptr) {
			memcpy(new_ptr, ptr, block->size);
			os_free(ptr);
		}
		return new_ptr;
	}
	return NULL;
}
