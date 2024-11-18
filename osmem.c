// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"

#define ALIGMENT 8
#define ALING(size) (((size) + (ALIGMENT - 1)) & ~(ALIGMENT - 1))
#define SIZE_T_SIZE (ALING(sizeof(struct block_meta)))
#define MMAP_THRESHOLD 131072

struct block_meta *head;

struct block_meta *find_best(size_t size)
{
	struct block_meta *best = NULL;
	struct block_meta *current = head;

	while (current) {
		if (current->status == STATUS_FREE && current->size >= ALING(size)) {
			if (best == NULL || current->size < best->size)
				best = current;
		}
		current = current->next;
	}

	return best;
}

void prealloc(void)
{
	if (head == NULL) {
		void *cap = sbrk(MMAP_THRESHOLD);

		DIE(cap == (void *) -1, "prealloc");
		head = (struct block_meta *) cap;
		head->status = STATUS_FREE;
		head->size = MMAP_THRESHOLD - SIZE_T_SIZE;
		head->next = NULL;
		head->prev = NULL;
	}
}

void coalesce(void)
{
	struct block_meta *node = head;

	while (node) {
		if (node->status == STATUS_FREE) {
			struct block_meta *next = node->next;
			size_t sum = node->size + SIZE_T_SIZE;

			while (next && next->status == STATUS_FREE) {
				sum += next->size + SIZE_T_SIZE;

				node->next = next->next;

				if (node->next)
					node->next->prev = node;

				next = node->next;
			}

			node->size = sum - SIZE_T_SIZE;
		}
	node = node->next;
	}
}

void split(struct block_meta **node, size_t size)
{
	struct block_meta *new = (void *) *node + SIZE_T_SIZE + ALING(size);

	new->size = (*node)->size - ALING(size) - SIZE_T_SIZE;
	new->status = STATUS_FREE;
	new->next = (*node)->next;
	new->prev = *node;

	(*node)->size = ALING(size);
	(*node)->status = STATUS_ALLOC;
	(*node)->next = new;
}

void *add_sbrk(size_t size)
{
	prealloc();
	struct block_meta *node = find_best(size);

	if (node) {
		if (node->size > ALING(size) + SIZE_T_SIZE)
			split(&node, size);
		else
			node->status = STATUS_ALLOC;
		return node;
	}
	struct block_meta *aux = head;

	while (aux->next)
		aux = aux->next;

	if (aux->status == STATUS_ALLOC) {
		void *new = sbrk(ALING(size) + SIZE_T_SIZE);

		DIE(new == (void *) -1, "add_block");
		struct block_meta *new_block = (struct block_meta *) new;

		new_block->status = STATUS_ALLOC;
		new_block->size = ALING(size);
		new_block->next = aux->next;
		new_block->prev = aux;
		aux->next = new_block;

		return (void *) new_block;
	} else if (aux->status == STATUS_FREE) {
		void *extra = sbrk(ALING(size) - aux->size);

		DIE(extra == (void *) -1, "expand_block");

		aux->status = STATUS_ALLOC;
		aux->size = ALING(size);

		return (void *) aux;
	}
	return NULL;
}

void *add_mmap(size_t size)
{
	void *node = mmap(NULL, ALING(size) + SIZE_T_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20, -1, 0);

	DIE(node == (void *)-1, "add_mmap");

	struct block_meta *block = (struct block_meta *) node;

	block->status = STATUS_MAPPED;
	block->size = ALING(size);
	block->next = NULL;
	block->prev = NULL;

	return node;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	void *node = NULL;

	if (ALING(size) + SIZE_T_SIZE < MMAP_THRESHOLD)
		node = add_sbrk(size);
	else
		node = add_mmap(size);

	return node + SIZE_T_SIZE;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *node = (struct block_meta *)(void *)(ptr - SIZE_T_SIZE);

	if (node->status == STATUS_MAPPED) {
		int res = munmap(node, node->size + SIZE_T_SIZE);

		DIE(res == -1, "free");

		return;
	}

	if (node->status == STATUS_ALLOC) {
		node->status = STATUS_FREE;
		coalesce();
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size * nmemb == 0)
		return NULL;

	void *node = NULL;

	if (ALING(size * nmemb) + SIZE_T_SIZE < 4096)
		node = add_sbrk(nmemb * size);
	else
		node = add_mmap(nmemb * size);

	struct block_meta *block = (struct block_meta *) node;

	node += SIZE_T_SIZE;
	memset(node, 0, block->size);

	return node;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *node = (struct block_meta *)(void *)(ptr - SIZE_T_SIZE);

	if (node->status == STATUS_FREE)
		return NULL;

	if (node->status == STATUS_MAPPED || ALING(size) > MMAP_THRESHOLD) {
		void *new = os_malloc(size);

		memcpy(new, ptr, ALING(size) < node->size ? ALING(size) : node->size);
		os_free(ptr);

		return new;
	}

	if (ALING(size) <= node->size) {
		if (node->size > ALING(size) + SIZE_T_SIZE)
			split(&node, size);

		return ptr;
	}

	if (node->next && node->next->status == STATUS_FREE && node->size + node->next->size + SIZE_T_SIZE >= ALING(size)) {
		struct block_meta *next = node->next;

		node->size += next->size + SIZE_T_SIZE;
		node->next = next->next;

		if (node->next)
			node->next->prev = node;

		if (node->size > ALING(size) + SIZE_T_SIZE)
			split(&node, size);

		return ptr;
	}

	return ptr;
}
