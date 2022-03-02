#ifndef __TC_H__
#define __TC_H__

#define TASK_SIZ 16

enum ip_proto {
	TCP_V4,
	TCP_V6,
	UDP_V4,
	UDP_V6
};

enum pkt_state {
	BLOCKED,
	ALLOWED
};

struct ip_info {
	enum ip_proto ipp;
	union  {
		uint8_t ipv6_addr[16];
		uint8_t ip4_addr[4];
	} addr;
	uint16_t port;
};

struct tc_evt {
	enum pkt_state state;
	pid_t tgid;
	pid_t pid;
	char comm[TASK_SIZ];
	uint16_t eth_type;
	union {
		struct ip_info ip;
		struct arphdr arp;
	};
};

#endif //__TC_H__
