#ifndef _ARP_H_
#define _ARP_H_

#include <stdlib.h>
#include <stdio.h>

struct ARPTableEntry
{
  u_int32_t prefix;
  u_int32_t mask;
  u_int32_t next_hop;
  int interface;
};
typedef struct ARPTableEntry *ARPEntry;

struct TrieNode
{
  struct TrieNode *left;
  struct TrieNode *right;
  struct ARPTableEntry *data;
  int flag;
};
typedef struct TrieNode *TNode;

extern TNode new_trie();

extern TNode new_trie_node(ARPEntry data);

extern void insert(TNode root, ARPEntry data);

extern ARPEntry search(TNode root, u_int32_t address);

extern void free_trie(TNode root);

#endif /* _ARP_H_ */