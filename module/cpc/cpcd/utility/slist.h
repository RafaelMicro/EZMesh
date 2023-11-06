/**
 * @file slist.h
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-08-03
 *
 * @copyright Copyright (c) 2023
 *
 */

#ifndef SLIST_H
#define SLIST_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

/// List node type
typedef struct slist_node slist_node_t;

/// List node
struct slist_node
{
    slist_node_t *node; ///< List node
};

#ifndef DOXYGEN
#define container_of(ptr, type, member) (type *)((uintptr_t)(ptr) - ((uintptr_t)(&((type *)0)->member)))

#define SLIST_ENTRY container_of

#define SLIST_FOR_EACH(slist_head, iterator) for ((iterator) = (slist_head); (iterator) != NULL; (iterator) = (iterator)->node)

#define SLIST_FOR_EACH_ENTRY(slist_head, entry, type, member) for ((entry) = SLIST_ENTRY(slist_head, type, member);     \
                                                                   (type *)(entry) != SLIST_ENTRY(NULL, type, member); \
                                                                   (entry) = SLIST_ENTRY((entry)->member.node, type, member))
#endif

void slist_init(slist_node_t **head);

void slist_push(slist_node_t **head, slist_node_t *item);

void slist_push_back(slist_node_t **head, slist_node_t *item);

slist_node_t *slist_pop(slist_node_t **head);

void slist_insert(slist_node_t *item, slist_node_t *pos);

void slist_remove(slist_node_t **head, slist_node_t *item);

void slist_sort(slist_node_t **head, bool (*cmp_fnct)(slist_node_t *item_l, slist_node_t *item_r));

#endif /* SLIST_H */
