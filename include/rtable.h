#ifndef _ARP_H_
#define _ARP_H_

#include <stdlib.h>
#include <stdio.h>

typedef struct route_table_entry *RTableEntry;

struct TrieNode
{
  struct TrieNode *left;
  struct TrieNode *right;
  struct ARPTableEntry *data;
  int flag;
};
typedef struct TrieNode *TNode;

extern TNode new_trie();

extern TNode new_trie_node(RTableEntry data);

extern void insert(TNode root, RTableEntry data);

extern RTableEntry search(TNode root, u_int32_t address);

extern void free_trie(TNode root);

#endif /* _ARP_H_ */