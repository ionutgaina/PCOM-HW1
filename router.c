#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "rtable.h"

struct iphdr *ip_hdr;
struct icmphdr *icmp_hdr;
struct ether_header *eth_hdr;
struct in_addr address;

int icmp_handler(char *packet, int len, int interface)
{
    printf("ICMP packet received\n");
    return 0;
}

int check_checksum(char *packet, int len)
{
    // checksum for ip
    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((void *)ip_hdr, sizeof(struct iphdr));

    if (old_checksum != new_checksum)
    {
        printf("Checksum error for iphdr\n");
        return 1;
    }

    // TODO checksum for icmp

    return 0;
}

void make_checksum()
{
    // it s working the checksum for ip
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((void *)ip_hdr, sizeof(struct iphdr)));

    // TO DO checksum for icmp
    if (ip_hdr->protocol == IPPROTO_ICMP)
    {
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = htons(checksum((void *)icmp_hdr, sizeof(struct icmphdr)));
    }
}

int ttl_handler(char *packet, int len, int interface)
{
    if (ip_hdr->ttl <= 1)
    {

        printf("TTL expired\n");

        // create eth
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
        uint8_t aux_mac[6];
        get_interface_mac(interface, aux_mac);
        memcpy(eth_hdr->ether_shost, aux_mac, 6);

        // create ip
        ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        ip_hdr->protocol = IPPROTO_ICMP;
        struct in_addr aux_ip;
        memcpy(&aux_ip, &ip_hdr->daddr, sizeof(struct in_addr));
        memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(struct in_addr));
        memcpy(&ip_hdr->saddr, &aux_ip, sizeof(struct in_addr));
        ip_hdr->ttl = 64;

        // create icmp
        icmp_hdr->type = TIME_EXCEEDED;
        icmp_hdr->code = 0;

        make_checksum();
        send_to_link(interface, packet, len + sizeof(struct icmphdr));
        return 1;
    }
    ip_hdr->ttl--;
    make_checksum();
    return 0;
}

RTableEntry rtable_handler(char *packet, int len, int interface, TNode trie)
{
    printf("Searching for route to host %d\n", ip_hdr->daddr);
    RTableEntry entry = search(trie, ip_hdr->daddr);
    if (entry == NULL)
    {
        printf("No route to host\n");

        // create eth
        uint8_t aux_mac[6]; 
        memcpy(aux_mac, eth_hdr->ether_dhost, 6);
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
        memcpy(eth_hdr->ether_shost, aux_mac, 6);

        // create ip
        ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        ip_hdr->protocol = IPPROTO_ICMP;
        struct in_addr aux_ip;
        memcpy(&aux_ip, &ip_hdr->daddr, sizeof(struct in_addr));
        // adresa sursa trebuie sa fie a mea
        memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(struct in_addr));
        memcpy(&ip_hdr->saddr, &address, sizeof(struct in_addr));
        ip_hdr->ttl = 64;

        // create icmp
        icmp_hdr->type = DEST_UNREACHABLE;
        icmp_hdr->code = 0;

        make_checksum();
        send_to_link(interface, packet, len + sizeof(struct icmphdr));
        return NULL;
    }

    printf("Found route to host %d\n", entry->prefix);
    printf("Next hop: %d\n", entry->next_hop);
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

    TNode rtable_trie = new_trie();

    for (int i = 0; i < rtable_len; i++)
    {
        insert(rtable_trie, &rtable[i]);
    }
    // read the mac table from the file

    struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * MAX_ARP_TABLE_ENTRIES);
    int arp_table_len = parse_arp_table("./arp_table.txt", arp_table);

    while (1)
    {
        int interface;
        size_t len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface <
                0,
            "recv_from_any_links");
        eth_hdr = (struct ether_header *)buf;
        ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
        icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

        // print ether_header
        printf("dest mac: %hhn\n src mac: %hhn\n", eth_hdr->ether_dhost, eth_hdr->ether_shost);

        // print iphdr header
        printf("tot_len: %d\n ttl: %d\n check: %d\n saddr: %d\n daddr: %d\n", ip_hdr->tot_len,
               ip_hdr->ttl, htons(ip_hdr->check), ip_hdr->saddr, ip_hdr->daddr);

        // get the ip address of the router
        inet_aton(get_interface_ip(interface), &address);

        // if ipv4 or arp
        // check the checksum
        if (check_checksum(buf, len))
            continue;

        // decrement the ttl
        if (ttl_handler(buf, len, interface))
            continue;
        // pana aici

        RTableEntry entry = rtable_handler(buf, len, interface, rtable_trie);

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

        // send the packet to the next hop
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
