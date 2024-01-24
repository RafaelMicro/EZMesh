#ifndef LIST_H
#define LIST_H

#ifdef __cplusplus
extern "C" {
#endif

// List node type
typedef struct slist_node list_node_t;

// List node
struct slist_node {
  list_node_t *node; // < List node
};

#define SLIST_ENTRY(ptr, T, member)                                            \
  (T *)((void *)(ptr) - ((void *)(&((T *)0)->member)))

// #define SLIST_ENTRY MEM_INDEX

#define SLIST_FOR_EACH(slist_head, iterator)                                   \
  for ((iterator) = (slist_head); (iterator) != NULL;                          \
       (iterator) = (iterator)->node)

#define SLIST_FOR_EACH_ENTRY(slist_head, entry, type, member)                  \
  for ((entry) = SLIST_ENTRY(slist_head, type, member);                        \
       (type *)(entry) != SLIST_ENTRY(NULL, type, member);                     \
       (entry) = SLIST_ENTRY((entry)->member.node, type, member))

void list_init(list_node_t **head);
void list_push(list_node_t **head, list_node_t *item);
void list_push_back(list_node_t **head, list_node_t *item);
list_node_t *list_pop(list_node_t **head);
void list_remove(list_node_t **head, list_node_t *item);

#ifdef __cplusplus
}
#endif

#endif /* LIST_H */
