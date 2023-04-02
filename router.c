#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "rtable.h"

int icmp_handler(char *packet, int len, int interface)
{
    // struct ether_header *eth_hdr = (struct ether_header *)packet;
    // struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    // struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    printf("ICMP packet received\n");
    return 0;
}

int check_checksum(char *packet, int len)
{
    // checksum for ip
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((void *)ip_hdr, sizeof(struct iphdr));

    if (old_checksum != new_checksum)
    {
        printf("Checksum error for iphdr\n");
        return 1;
    }

    // checksum for icmp
    // struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // old_checksum = ntohs(icmp_hdr->checksum);
    // icmp_hdr->checksum = 0;
    // new_checksum = checksum((void *)icmp_hdr, sizeof(struct icmphdr));

    // if (old_checksum != new_checksum)
    // {
    //     printf("%d %d\n", old_checksum, new_checksum);
    //     printf("Checksum error for icmp\n");
    //     return 1;
    // }

    return 0;
}


void make_checksum(char *packet, int len)
{
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    ip_hdr->check = 0;
    ip_hdr->check = checksum((void *)ip_hdr, sizeof(struct iphdr));
}

int ttl_handler(char *packet, int len, int interface)
{
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    if (ip_hdr->ttl <= 1)
    {
        printf("TTL expired\n");
        icmp_hdr->type = TIME_EXCEEDED;
        icmp_hdr->code = 0;
        make_checksum(packet, len);
        send_to_link(interface, packet, len);
        return 1;
    }
    ip_hdr->ttl--;
    return 0;
}

// it will return an entry from the routing table
RTableEntry rtable_handler(char *packet, int len, int interface, struct route_table_entry *rtable, int rtable_len)
{
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    RTableEntry entry = NULL;

    for (int i = 0; i < rtable_len; i++)
    {
        if ((ip_hdr->daddr & rtable[i].mask) == rtable[i].prefix)
        {
            if (entry == NULL)
            {
                entry = &rtable[i];
            }
            else
            {
                if (entry->mask < rtable[i].mask)
                {
                    entry = &rtable[i];
                }
            }
        }
    }
    if (entry == NULL)
    {
        printf("No route to host\n");
        icmp_hdr->type = DEST_UNREACHABLE;
        icmp_hdr->code = 0;
        make_checksum(packet, len);
        send_to_link(interface, packet, len);
        return NULL;
    }

    printf("Found route to host %d\n", entry->prefix);
    return entry;
}

struct arp_entry *get_arp_entry(uint32_t address, struct arp_entry *arp_table, int arp_table_len)
{

    for (int i = 0; i < arp_table_len; i++)
    {
        if (arp_table[i].ip == address)
        {
            return &arp_table[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // read the routing table from the file
    struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
    int rtable_len = read_rtable(argv[1], rtable);

    // TNode rtable_trie = new_trie();

    // for (int i = 0; i < rtable_len; i++)
    // {
    //     insert(rtable_trie, &rtable[i]);
    // }
    // read the mac table from the file

    struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * MAX_ARP_TABLE_ENTRIES);
    int arp_table_len = parse_arp_table("./arp_table.txt", arp_table);

    struct in_addr address;
    while (1)
    {
        int interface;
        size_t len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface <
                0,
            "recv_from_any_links");
        struct ether_header *eth_hdr = (struct ether_header *)buf;
        struct iphdr
            *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

        // print ether_header
        printf("dest mac: %hhn\n src mac: %hhn\n ether_type: %d\n", eth_hdr->ether_dhost, eth_hdr->ether_shost,
               eth_hdr->ether_type);

        // print iphdr header
        printf("tot_len: %d\n id: %d\n ttl: %d\n check: %d\n saddr: %d\n daddr: %d\n", ip_hdr->tot_len,
               ip_hdr->id, ip_hdr->ttl, htons(ip_hdr->check), ip_hdr->saddr, ip_hdr->daddr);

        // get the ip address of the router
        inet_aton(get_interface_ip(interface), &address);

        // verify if the packet is IPv4 or ARP
        if (eth_hdr->ether_type != htons(IPv4) && eth_hdr->ether_type != htons(ARP))
            continue;

        // check the checksum
        if (check_checksum(buf, len))
            continue;

        // decrement the ttl
        if (ttl_handler(buf, len, interface))
            continue;

        RTableEntry entry = rtable_handler(buf, len, interface, rtable, rtable_len);

        if (entry == NULL)
            continue;

        // search for the mac address in the arp table
        struct arp_entry *arp_entry = get_arp_entry(entry->next_hop, arp_table, arp_table_len);

        if (arp_entry == NULL)
        {
            printf("No ARP entry for next hop\n");
            continue;
        }

        // set the mac address of the next hop
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

        make_checksum(buf, len);
        send_to_link(entry->interface, buf, len);

        // if the packet is ICMP
        // if (ip_hdr->protocol == IPPROTO_ICMP)
        // {
        //     // if the packet is for this router
        //     if (ip_hdr->daddr == address.s_addr)
        //     {
        //         icmp_handler(buf, len, interface);
        //     }
        //     continue;
        // }
    }
}
