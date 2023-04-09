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
    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((void *)ip_hdr, sizeof(struct iphdr));

    if (old_checksum != new_checksum)
    {
        printf("Checksum error for iphdr\n");
        return 1;
    }

    return 0;
}

void make_checksum()
{
    // checksum for ip
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((void *)ip_hdr, sizeof(struct iphdr)));

    // checksum for icmp
    if (ip_hdr->protocol == IPPROTO_ICMP)
    {
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = htons(checksum((void *)icmp_hdr, sizeof(struct icmphdr) + ntohs(ip_hdr->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr)));
    }
}

int ttl_handler(char *packet, int len, int interface)
{
    if (ip_hdr->ttl <= 1)
    {

        int data_len = sizeof(struct iphdr) + 8;
        char *data = malloc(data_len);
        memcpy(data, packet + sizeof(struct ether_header), data_len);
        printf("TTL expired\n");

        // create eth
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
        uint8_t aux_mac[MAC_LEN];
        get_interface_mac(interface, aux_mac);
        memcpy(eth_hdr->ether_shost, aux_mac, MAC_LEN);

        // create ip
        ip_hdr->tot_len = htons(data_len + sizeof(struct iphdr) + sizeof(struct icmphdr));
        ip_hdr->protocol = IPPROTO_ICMP;
        memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(struct in_addr));
        memcpy(&ip_hdr->saddr, &address, sizeof(struct in_addr));
        ip_hdr->ttl = 64;

        // create icmp
        icmp_hdr->type = TIME_EXCEEDED;
        icmp_hdr->code = 0;

        icmp_hdr->un.echo.id = 0;
        icmp_hdr->un.echo.sequence = 0;

        icmp_hdr->un.frag.mtu = 0;
        icmp_hdr->un.frag.mtu = 0;

        memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, data_len);

        int packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len;
        make_checksum();
        send_to_link(interface, packet, packet_len);
        return 1;
    }
    ip_hdr->ttl--;
    make_checksum();
    return 0;
}

RTableEntry rtable_handler(char *packet, int interface, TNode trie)
{
    printf("Searching for route to host %u\n", ip_hdr->daddr);
    RTableEntry entry = search(trie, ip_hdr->daddr);
    if (entry == NULL)
    {
        printf("No route to host\n");
        int data_len = sizeof(struct iphdr) + 8;
        char *data = malloc(data_len);
        memcpy(data, packet + sizeof(struct ether_header), data_len);
        // create eth
        uint8_t aux_mac[MAC_LEN];
        memcpy(aux_mac, eth_hdr->ether_dhost, MAC_LEN);
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
        memcpy(eth_hdr->ether_shost, aux_mac, MAC_LEN);

        // create ip
        ip_hdr->protocol = IPPROTO_ICMP;
        ip_hdr->tot_len = htons(data_len + sizeof(struct iphdr) + sizeof(struct icmphdr));
        ip_hdr->protocol = IPPROTO_ICMP;
        memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(struct in_addr));
        memcpy(&ip_hdr->saddr, &address, sizeof(struct in_addr));
        ip_hdr->ttl = 64;

        // create icmp
        icmp_hdr->type = DEST_UNREACHABLE;
        icmp_hdr->code = 0;

        icmp_hdr->un.echo.id = 0;
        icmp_hdr->un.echo.sequence = 0;

        icmp_hdr->un.frag.mtu = 0;
        icmp_hdr->un.frag.mtu = 0;

        memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), data, data_len);

        int packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len;
        make_checksum();
        send_to_link(interface, packet, packet_len);
        return NULL;
    }

    printf("Found route to host %d\n", entry->prefix);
    printf("Next hop: %d\n", entry->next_hop);
    return entry;
}

void echo_reply_handler(char *packet, int len, int interface)
{
    printf("Echo reply packet received\n");

    // create eth
    uint8_t aux_mac[MAC_LEN];
    memcpy(aux_mac, eth_hdr->ether_dhost, MAC_LEN);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
    memcpy(eth_hdr->ether_shost, aux_mac, MAC_LEN);

    // create ip
    struct in_addr aux_ip;
    memcpy(&aux_ip, &ip_hdr->daddr, sizeof(struct in_addr));
    memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(struct in_addr));
    memcpy(&ip_hdr->saddr, &aux_ip, sizeof(struct in_addr));
    ip_hdr->ttl = 64;

    // create icmp
    icmp_hdr->type = ECHO_REPLY;
    icmp_hdr->code = 0;

    make_checksum();
    send_to_link(interface, packet, len);
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

void arp_handler(RTableEntry entry)
{
    char *arp_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
    struct ether_header *arp_eth_hdr = (struct ether_header *)arp_packet;
    struct arp_header *arp_hdr = (struct arp_header *)(arp_packet + sizeof(struct ether_header));

    // create eth
    uint8_t broadcast_mac[MAC_LEN] = {255, 255, 255, 255, 255, 255};

    memcpy(arp_eth_hdr->ether_dhost, broadcast_mac, MAC_LEN);
    get_interface_mac(entry->interface, arp_eth_hdr->ether_shost);

    arp_eth_hdr->ether_type = htons(ARP);

    // create arp
    arp_hdr->htype = htons(1);
    arp_hdr->ptype = htons(0x0800);
    arp_hdr->hlen = MAC_LEN;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(1);
    get_interface_mac(entry->interface, arp_hdr->sha);

    struct in_addr my_address;
    inet_aton(get_interface_ip(entry->interface), &my_address);
    memcpy(&arp_hdr->spa, &my_address.s_addr, sizeof(uint32_t));

    memset(arp_hdr->tha, 0, MAC_LEN);
    memcpy(&arp_hdr->tpa, &entry->next_hop, sizeof(uint32_t));

    printf("Send ARP request\n");
    send_to_link(entry->interface, arp_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int main(int argc, char *argv[])
{
    char *buf = malloc(MAX_PACKET_LEN);

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

    // create arp table
    struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * MAX_ARP_TABLE_ENTRIES);
    int arp_table_len = 0;

    // arp request queue
    queue packet_queue = queue_create();
    queue packet_len = queue_create();

    struct in_addr latest_address;

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

        struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

        // get the ip address of the router
        inet_aton(get_interface_ip(interface), &address);

        struct arp_entry *arp_entry = NULL;
        RTableEntry entry = NULL;
        printf("am primit ceva\n");
        if (ntohs(eth_hdr->ether_type) == IPv4)
        {

            // check the checksum
            if (check_checksum(buf, len))
                continue;

            // decrement the ttl
            if (ttl_handler(buf, len, interface))
                continue;

            if (ntohl(ip_hdr->daddr) == ntohl(address.s_addr))
            {
                // echo reply
                printf("Packet from me\n");
                echo_reply_handler(buf, len, interface);
                continue;
            }

            entry = rtable_handler(buf, interface, rtable_trie);

            if (entry == NULL)
                continue;

            // search for the mac address in the arp table
            arp_entry = get_arp_entry(entry->next_hop, arp_table, arp_table_len);
        }
        else
        {

            if (ntohs(arp_hdr->op) == 1)
            {
                // if the arp packet is for me
                if (ntohl(arp_hdr->tpa) == ntohl(address.s_addr))
                {
                    // arp reply
                    printf("ARP reply send\n");
                    arp_hdr->op = htons(2);

                    memcpy(arp_hdr->tha, arp_hdr->sha, MAC_LEN);
                    get_interface_mac(interface, arp_hdr->sha);

                    memcpy(&arp_hdr->tpa, &arp_hdr->spa, sizeof(uint32_t));
                    memcpy(&arp_hdr->spa, &address.s_addr, sizeof(uint32_t));

                    // eth
                    memcpy(eth_hdr->ether_dhost, arp_hdr->tha, MAC_LEN);
                    memcpy(eth_hdr->ether_shost, arp_hdr->sha, MAC_LEN);
                    send_to_link(interface, buf, len);
                    continue;
                }
                if (ntohl(arp_hdr->tpa) == ntohl(latest_address.s_addr))
                    continue;
                // arp request
                printf("ARP transfer\n");

                struct ether_header *arp_eth_hdr = (struct ether_header *)buf;
                struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

                get_interface_mac(interface, arp_hdr->sha);
                memcpy(&arp_hdr->spa, &address.s_addr, sizeof(uint32_t));

                memcpy(arp_eth_hdr->ether_shost, arp_hdr->sha, MAC_LEN);

                send_to_link(interface, buf, len);
                continue;
            }

            if (ntohs(arp_hdr->op) == 2)
            {
                // add the entry to the arp table
                printf("Received reply\n");
                arp_entry = malloc(sizeof(struct arp_entry));
                arp_entry->ip = arp_hdr->spa;
                memcpy(&arp_entry->mac, &arp_hdr->sha, MAC_LEN);

                if (get_arp_entry(arp_entry->ip, arp_table, arp_table_len) == NULL)
                {
                    printf("Add entry to arp table\n");
                    printf("ip: %d\n", arp_entry->ip);

                    arp_table[arp_table_len].ip = arp_entry->ip;
                    memcpy(arp_table[arp_table_len].mac, arp_entry->mac, MAC_LEN);
                    arp_table_len++;
                }

                if (queue_empty(packet_queue))
                    continue;

                printf("Send packets from queue\n");
                // send the packets from the queue
                char *packet = queue_deq(packet_queue);
                int len = *(int *)queue_deq(packet_len);
                eth_hdr = (struct ether_header *)packet;
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);

                ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
                icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

                printf("ip scos din coada: %u\n", ip_hdr->daddr);
                entry = rtable_handler(packet, interface, rtable_trie);
                get_interface_mac(entry->interface, eth_hdr->ether_shost);
                send_to_link(entry->interface, packet, len);
                continue;
            }
        }

        if (arp_entry == NULL)
        {
            // send arp request
            printf("ip adaugat in coada: %u\n", ip_hdr->daddr);
            char *new_buf = malloc(len);
            memcpy(new_buf, buf, len);
            queue_enq(packet_queue, new_buf);
            size_t *new_len = malloc(sizeof(size_t));
            *new_len = len;
            queue_enq(packet_len, new_len);
            latest_address.s_addr = ip_hdr->daddr;
            arp_handler(entry);
            continue;
        }

        // set the mac address of the next hop
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, MAC_LEN);

        // send the packet to the next hop
        send_to_link(entry->interface, buf, len);
    }
}
