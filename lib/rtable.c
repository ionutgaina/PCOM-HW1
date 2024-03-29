#include "rtable.h"

TNode new_trie()
{
  TNode node = malloc(sizeof(struct TrieNode));
  node->data = NULL;
  node->left = NULL;
  node->right = NULL;
  node->flag = 0;
  return node;
}

TNode new_trie_node(RTableEntry data)
{
  TNode node = new_trie();
  node->data = data;
  return node;
}

void insert(TNode root, RTableEntry data)
{
  // we will use this bit to check if the bit is set or not from the left to the right
  u_int32_t bit = 1u << 31; //

  if (data->prefix == 0)
  {
    return;
  }

  while (bit & htonl(data->mask))
  {
    // if the bit is set
    if (bit & htonl(data->prefix))
    {
      // if the right node is null, we create a new node
      if (root->right == NULL)
      {
        root->right = new_trie();
      }

      // we move to the right node
      root = root->right;
    }
    else
    {
      // if the left node is null, we create a new node
      if (root->left == NULL)
      {
        root->left = new_trie();
      }

      // we move to the left node
      root = root->left;
    }
    // we shift the bit to the right
    bit >>= 1;
  }
  // we set the data of the node
  root->data = data;
  root->flag = 1;
}

RTableEntry search(TNode root, u_int32_t address)
{
  if (root == NULL)
  {
    return NULL;
  }

  u_int32_t bit = 1u << 31;
  RTableEntry data = NULL;


  while (bit)
  {

    if (root->flag == 1)
    {
      data = root->data;
    }

    if (bit & htonl(address))
    {
      if (root->right == NULL)
      {
        return data;
      }
      root = root->right;
    }
    else
    {
      if (root->left == NULL)
      {
        return data;
      }
      root = root->left;
    }
    bit >>= 1;
  }
  return data;
}

void free_trie(TNode root)
{
  if (root == NULL)
  {
    return;
  }

  if (root->data != NULL)
  {
    free(root->data);
  }

  free_trie(root->left);
  free_trie(root->right);
  free(root);
}
