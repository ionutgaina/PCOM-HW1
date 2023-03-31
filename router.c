#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "arp.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	printf("hello");
	// test arp tree
	TNode root = new_trie();
	ARPEntry entry = malloc(sizeof(struct ARPTableEntry));

	// 192.1.4.0
	entry->prefix = 0xC0010400;

	// 192.1.4.2
	entry->next_hop = 0xC0010402;

	// 255.255.255.0
	entry->mask = 0xFFFFFF00;

	// 1
	entry->interface = 1;
	printf("hello\n");
	insert(root, entry);
	printf("\n");

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}
