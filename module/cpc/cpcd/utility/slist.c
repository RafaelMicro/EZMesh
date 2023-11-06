/**
 * @file slist.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-08-03
 *
 * @copyright Copyright (c) 2023
 *
 */


#include "slist.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>


void slist_init(slist_node_t **head)
{
    *head = 0;
}


void slist_push(slist_node_t **head,
                slist_node_t *item)
{
    item->node = *head;
    *head = item;
}

void slist_push_back(slist_node_t **head,
                     slist_node_t *item)
{
    slist_node_t **node_ptr = head;

    while (*node_ptr != NULL)
    {
        node_ptr = &((*node_ptr)->node);
    }

    item->node = NULL;
    *node_ptr = item;
}

slist_node_t *slist_pop(slist_node_t **head)
{
    slist_node_t *item;

    item = *head;
    if (item == NULL)
    {
        return(NULL);
    }

    *head = item->node;

    item->node = NULL;

    return(item);
}


void slist_insert(slist_node_t *item,
                  slist_node_t *pos)
{
    item->node = pos->node;
    pos->node = item;
}

void slist_remove(slist_node_t **head,
                  slist_node_t *item)
{
    slist_node_t **node_ptr;

    for (node_ptr = head; *node_ptr != NULL; node_ptr = &((*node_ptr)->node))
    {
        if (*node_ptr == item)
        {
            *node_ptr = item->node;
            return;
        }
    }
}

void slist_sort(slist_node_t **head,
                bool (*cmp_fnct)(slist_node_t *item_l,
                                 slist_node_t *item_r))
{
    bool swapped;
    slist_node_t **pp_item_l;

    do
    {
        swapped = false;

        pp_item_l = head;
        // Loop until end of list is found.
        while ((*pp_item_l != NULL) && ((*pp_item_l)->node != NULL))
        {
            slist_node_t *p_item_r = (*pp_item_l)->node;
            bool ordered;

            // Call provided compare fnct.
            ordered = cmp_fnct(*pp_item_l, p_item_r);
            if (ordered == false)
            {
                // If order is not correct, swap items.
                slist_node_t *p_tmp = p_item_r->node;

                // Swap the two items.
                p_item_r->node = *pp_item_l;
                (*pp_item_l)->node = p_tmp;
                *pp_item_l = p_item_r;
                pp_item_l = &(p_item_r->node);
                // Indicate a swap has been done.
                swapped = true;
            } else
            {
                pp_item_l = &((*pp_item_l)->node);
            }
        }
        // Re-loop until no items have been swapped.
    } while (swapped == true);
}
