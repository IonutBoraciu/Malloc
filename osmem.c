// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define STATUS_FREE 0
#define STATUS_ALLOC 1
#define STATUS_MAPPED 2
#define MAX_VAL (128 * 1024)
#define PROT_READ 0x1  /* Page can be read.  */
#define PROT_WRITE 0x2 /* Page can be written.  */
#define PROT_EXEC 0x4  /* Page can be executed.  */
#define PROT_NONE 0x0  /* Page can not be accessed.  */

#define MAP_SHARED 0x01    /* Share changes.  */
#define MAP_PRIVATE 0x02   /* Changes are private.  */
#define MAP_ANONYMOUS 0x20 /* Don't use a file.  */
#define MAP_ANON MAP_ANONYMOUS
#define METADATA_SIZE (sizeof(struct block_meta))
#define MOCK_PREALLOC (128 * 1024 - METADATA_SIZE - 8)
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGN(size) (((size) + 7) & ~7)
struct block_meta {
	size_t size;
	int status;
	struct block_meta *prev;
	struct block_meta *next;
};
struct block_meta *head;
struct block_meta *head_mmap;
// struct block_meta* head_mmap;

struct block_meta *insert_best(size_t size)
{
	int struct_size = ALIGN(sizeof(struct block_meta));
	struct block_meta *curr = head;
	struct block_meta *best = NULL;

	size = ALIGN(size);

	while (curr != NULL) {
		if (ALIGN(size + struct_size) <= curr->size &&
			curr->status == STATUS_FREE) {
			if (best != NULL) {
				if (best->size >= curr->size)
					best = curr;
			} else {
				best = curr;
			}
		}
	curr = curr->next;
	}
	curr = head;
	while (curr != NULL) {
		if (curr == best) {
			if (ALIGN(size + 2 * struct_size + 8) <= curr->size) {
				struct block_meta *after_split =
				(struct block_meta *)((char *)curr + ALIGN(size) + struct_size);
				after_split->next = curr->next;
				after_split->prev = curr;
				after_split->size = ALIGN(curr->size - size - struct_size);
				curr->next = after_split;
				after_split->status = STATUS_FREE;
				curr->status = STATUS_ALLOC;
				curr->size = ALIGN(size + struct_size);
				return (void *)((char *)curr + struct_size);
			}
			curr->status = STATUS_ALLOC;
			return (void *)((char *)curr + struct_size);
		}
		curr = curr->next;
	}
	return NULL;
}

void merge_blocks(void)
{
	int struct_size = ALIGN(sizeof(struct block_meta));
	struct block_meta *curr = head;

	while (curr->next != NULL) {
		if (curr->status == STATUS_FREE && curr->next->status == STATUS_FREE) {
			curr->size = curr->size + curr->next->size - struct_size;
			curr->next->prev = NULL;
			curr->next = curr->next->next;
		}
		curr = curr->next;
		if (curr == NULL)
			break;
	}
}

void *os_malloc(size_t size)
{
	static int check_if_mmap;
	static int remaining;

	if (size == 0)
		return NULL;

	int struct_size = ALIGN(sizeof(struct block_meta));
	void *allocated = NULL;

	if (size >= MAX_VAL && head_mmap == NULL) {
		allocated = mmap(NULL, struct_size + size, PROT_READ | PROT_WRITE,
						MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		head_mmap = (struct block_meta *)(allocated);
		head_mmap->status = STATUS_MAPPED;
		head_mmap->size = size + struct_size;
		check_if_mmap = 1;
		return allocated + struct_size;
	} else if (head == NULL) {
		allocated = sbrk(MAX_VAL);
		head = (struct block_meta *)(allocated);
		head->status = STATUS_ALLOC;
		head->size = ALIGN(size + struct_size);
		struct block_meta *block;

		remaining = 0;
		if (head->size <= 131000) {
			remaining = 1;
			block = (struct block_meta *)(allocated + head->size);
			block->status = STATUS_FREE;
			block->size = ALIGN(MAX_VAL - head->size - struct_size);
			block->prev = head;
			block->next = NULL;
			head->next = block;
		}
		return allocated + struct_size;
	} else if (head != NULL && size < MAX_VAL) {
		struct block_meta *curr = head;

		merge_blocks();
		merge_blocks();
		merge_blocks();
		void *a = insert_best(size);

		if (a != NULL)
			return a;
		while (curr->next != NULL)
			curr = curr->next;
		if (curr->status == STATUS_FREE) {
			int size_to_be_added = curr->size - struct_size;
			int hope_not_neg = ALIGN(size - size_to_be_added);

			curr->status = STATUS_ALLOC;
			curr->size = curr->size + ALIGN(hope_not_neg);
			if (hope_not_neg < 0)
				hope_not_neg = -hope_not_neg;
			void *ign = sbrk(ALIGN(hope_not_neg));

			curr->next = NULL;
			return (void *)(curr + 1);
		}
		void *nou = sbrk(ALIGN(size + struct_size));
		struct block_meta *next = (struct block_meta *)nou;

		next->status = STATUS_ALLOC;
		next->size = ALIGN(size + struct_size);
		curr->next = next;
		next->prev = curr;
		return nou + struct_size;
	}
	struct block_meta *next;

	if (check_if_mmap == 1) {
		next = head_mmap;
		while (next->next != NULL)
			next = next->next;
	}
	allocated = mmap(NULL, ALIGN(struct_size + size), PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (check_if_mmap == 1) {
		struct block_meta *new_node = (struct block_meta *)(allocated);

		new_node->status = STATUS_MAPPED;
		new_node->size = ALIGN(size + struct_size);
		next->next = new_node;
		new_node->prev = next;
		return allocated + struct_size;
	}
	head_mmap = (struct block_meta *)(allocated);
	head_mmap->status = STATUS_MAPPED;
	head_mmap->size = size + struct_size;
	check_if_mmap = 1;
	return allocated + struct_size;
}

void os_free(void *ptr)
{
	int struct_size = ALIGN(sizeof(struct block_meta));
	struct block_meta *current = head_mmap;
	struct block_meta *prev = NULL;
	struct block_meta *current2 = head;

	while (current2 != NULL) {
		if ((void *)current2 + struct_size == ptr) {
			current2->status = STATUS_FREE;
			break;
		}
		current2 = current2->next;
	}
	while (current != NULL) {
		if ((void *)current + struct_size == ptr) {
			if (current->status == STATUS_MAPPED) {
				if (prev != NULL)
					prev->next = current->next;
				else
					head_mmap = current->next;
				munmap(current, current->size);
				break;
			}
		}
		prev = current;
		current = current->next;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	static int check_if_mmap;
	static int remaining;

	if (size * nmemb == 0)
		return NULL;

	int struct_size = ALIGN(sizeof(struct block_meta));
	void *allocated = NULL;

	if (size * nmemb + struct_size >= 4096 && head_mmap == NULL) {
		allocated = mmap(NULL, struct_size + size * nmemb, PROT_READ | PROT_WRITE,
						MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		head_mmap = (struct block_meta *)(allocated);
		head_mmap->status = STATUS_MAPPED;
		head_mmap->size = size * nmemb + struct_size;
		check_if_mmap = 1;
		return allocated + struct_size;
	} else if (head == NULL) {
		allocated = sbrk(MAX_VAL);
		head = (struct block_meta *)(allocated);
		head->status = STATUS_ALLOC;
		head->size = ALIGN(size * nmemb + struct_size);
		struct block_meta *block;

		remaining = 0;
		if (head->size <= 4056) {
			remaining = 1;
			block = (struct block_meta *)(allocated + head->size);
			block->status = STATUS_FREE;
			block->size = ALIGN(MAX_VAL - head->size - struct_size);
			block->prev = head;
			block->next = NULL;
			head->next = block;
		}
		memset(allocated + struct_size, 0, size * nmemb);
		return allocated + struct_size;
	} else if (head != NULL && size * nmemb < 4096) {
		struct block_meta *curr = head;

		merge_blocks();
		merge_blocks();
		merge_blocks();
		merge_blocks();
		merge_blocks();
		merge_blocks();
		void *a = insert_best(size * nmemb);

		if (a != NULL) {
			memset(a, 0, size * nmemb);
			return a;
		}
		while (curr->next != NULL)
			curr = curr->next;
		if (curr->status == STATUS_FREE) {
			int size_to_be_added = curr->size - struct_size;
			int hope_not_neg = ALIGN(size * nmemb - size_to_be_added);

			curr->status = STATUS_ALLOC;
			curr->size = curr->size + ALIGN(hope_not_neg);
			if (hope_not_neg < 0)
				hope_not_neg = -hope_not_neg;
			void *ign = sbrk(ALIGN(hope_not_neg));

			curr->next = NULL;
			memset(curr + 1, 0, curr->size);
			return (void *)(curr + 1);
		}
		void *nou = sbrk(ALIGN(size * nmemb + struct_size));
		struct block_meta *next = (struct block_meta *)nou;

		next->status = STATUS_ALLOC;
		next->size = ALIGN(size * nmemb + struct_size);
		curr->next = next;
		next->prev = curr;
		memset(nou + struct_size, 0, size * nmemb);
		return nou + struct_size;
	}
	struct block_meta *next;

	if (check_if_mmap == 1) {
		next = head_mmap;
		while (next->next != NULL)
			next = next->next;
	}
	allocated =
			mmap(NULL, ALIGN(struct_size + size * nmemb), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (check_if_mmap == 1) {
		struct block_meta *new_node = (struct block_meta *)(allocated);

		new_node->status = STATUS_MAPPED;
		new_node->size = ALIGN(size * nmemb + struct_size);
		next->next = new_node;
		new_node->prev = next;
		memset(allocated + struct_size, 0, size * nmemb);
		return allocated + struct_size;
	}
	head_mmap = (struct block_meta *)(allocated);
	head_mmap->status = STATUS_MAPPED;
	head_mmap->size = size * nmemb + struct_size;
	check_if_mmap = 1;
	memset(allocated + struct_size, 0, size * nmemb);
	return allocated + struct_size;
}

void *os_realloc(void *ptr, size_t size)
{
	int struct_size = ALIGN(sizeof(struct block_meta));

	if (ptr == NULL) {
		ptr = os_malloc(size);
		return ptr;
	}
	struct block_meta *curr = head;

	while (curr != NULL) {
		if ((void *)curr + struct_size == ptr) {
			if (curr->next != NULL) {
				if (curr->next->size + curr->size < ALIGN(size) &&
					curr->status != STATUS_MAPPED) {
					os_free(ptr);
					void *a = os_malloc(size);
					return a;
				}
		  // to do repair bug
				if (curr->next->status == STATUS_FREE && curr->size < ALIGN(size)) {
					curr->size = curr->size + ALIGN(size - curr->size);
					curr->next =
							(char *)(curr->next + ALIGN(size - curr->size));
					curr->next->size =
					curr->next->size - ALIGN(size - curr->size);
					return (void *)((char *)curr + struct_size);
				} else if (curr->size < ALIGN(size) &&
						curr->status != STATUS_MAPPED) {
					if (curr->size + struct_size + 8 < ALIGN(size)) {
						struct block_meta *new_block =
								(char *)(curr + ALIGN(size + struct_size));

						new_block->size = ALIGN(curr->size - struct_size - size);
						new_block->status = STATUS_FREE;
						new_block->next = curr->next;
						curr->next = new_block;
					}
					curr->size = ALIGN(size + struct_size);
					return (void *)((char *)curr + struct_size);
				}
			os_free(ptr);
			void *a = os_malloc(size);
			return a;
			} else {
				os_free(ptr);
				void *a = os_malloc(size);
				return a;
			}
		}
		curr = curr->next;
	}
	void *a = os_malloc(size);

	os_free(ptr);
	return a;
}


