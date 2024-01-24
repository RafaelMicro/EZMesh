
#include "list.h"
#include <stdlib.h>

void list_init(list_node_t **head) { *head = 0; }

void list_push(list_node_t **head, list_node_t *item) {
  item->node = *head;
  *head = item;
}

void list_push_back(list_node_t **head, list_node_t *item) {
  list_node_t **node_ptr = head;

  while (*node_ptr != NULL) node_ptr = &((*node_ptr)->node);
  item->node = NULL;
  *node_ptr = item;
}

list_node_t *list_pop(list_node_t **head) {
  list_node_t *item;
  
  item = *head;
  if (item == NULL) return NULL;
  *head = item->node;
  item->node = NULL;
  return (item);
}

void list_remove(list_node_t **head, list_node_t *item) {
  list_node_t **node_ptr;
  node_ptr = head;
  while (*node_ptr != NULL) {
    if (*node_ptr == item) {
      *node_ptr = item->node;
      break;
    }
    node_ptr = &((*node_ptr)->node);
  }
  return;
}
