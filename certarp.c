/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IP_0 RTE_IPV4(88, 0, 174, 171)
#define IP_1 RTE_IPV4(87, 0, 174, 171)

#define MAX_CERT_COUNT 5
#define CERT_COUNT 2
#define CERT_PATHS {"rootCA.der", "domain-signed.der"}

#define KEY_PATH "domain.key"

/* certarp.c: Modified from the basic DPDK skeleton forwarding example. */

/* Custom ARP with certificates header. */
struct cert_arp_hdr {
	uint16_t cert_index;
	uint16_t cert_total_count;
	uint16_t cert_len;
	uint32_t sig_len;
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */


static inline int
send_arp_request(uint16_t port, struct rte_arp_ipv4 *arp_data, struct rte_mempool *mbuf_pool)
{
	struct rte_arp_hdr *ah;
	struct rte_arp_ipv4 *ad;
	struct rte_ether_hdr *eh;
	struct rte_ether_addr addr;
	struct rte_mbuf *bf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(bf == NULL)) {
		printf("failed to allocate a pktmbuf.\n");
		return 1;
	}
	ah = (struct rte_arp_hdr *) rte_pktmbuf_prepend(bf, (uint16_t) sizeof(struct rte_arp_hdr));
	ah->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	ah->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	ah->arp_hlen = RTE_ETHER_ADDR_LEN;
	ah->arp_plen = sizeof(uint32_t);
	ah->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
	ah->arp_data = *arp_data;
	eh = (struct rte_ether_hdr *) rte_pktmbuf_prepend(bf, (uint16_t) sizeof(struct rte_ether_hdr));
	eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	eh->src_addr = arp_data->arp_sha;
	eh->dst_addr = arp_data->arp_tha;
	const uint16_t _nb_tx = rte_eth_tx_burst(port, 0, &bf, 1);
	if (unlikely(_nb_tx < 1)) {
		printf("\nfailed to transmit the request packet.\n");
		return 1;
	}
	else {
		printf("\ntransmitted the ARP request.\n");
		return 0;
	}
}

static inline void
replace_all(char *s, char old, char new, size_t len)
{
	for (int i=0; i<len; ++i) {
		if (s[i] == old) s[i] = new;
	}
}

static inline int
handle_arp_request(
	struct rte_mempool *mbuf_pool,
	uint16_t port,
	struct rte_mbuf *buf,
	struct rte_ether_hdr *eh,
	struct rte_arp_hdr *ah,
	struct rte_ether_addr *eth_addr,
	uint32_t ip_addr,
	X509 **certs,  // DER certificates
	const uint16_t cert_cnt,
	RSA *rsa)
{
	struct rte_arp_ipv4 *ad = &(ah->arp_data);
	/* Prepare the ARP reply packet. */
	ad->arp_tha = ad->arp_sha;
	ad->arp_tip = ad->arp_sip;
	rte_ether_addr_copy(eth_addr, &(ad->arp_sha));
	ad->arp_sip = ip_addr;
	ah->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* Prepend the ethernet header and trim the payload. */
	rte_ether_addr_copy(eth_addr, &(eh->src_addr));
	rte_ether_addr_copy(&(ad->arp_tha), &(eh->dst_addr));
	uint16_t trim_len = buf->pkt_len - sizeof(struct rte_arp_hdr) - sizeof(struct rte_ether_hdr);
	rte_pktmbuf_trim(buf, trim_len);

	for (uint16_t cert_index=0; cert_index<cert_cnt; ++cert_index) {
		struct rte_mbuf *new_buf = rte_pktmbuf_clone(buf, mbuf_pool);
		if (unlikely(new_buf == NULL)) {
			printf("failed to clone an mbuf.\n");
			return 1;
		}
		X509 *cert_payload;
		X509 *cert = certs[cert_index];
		struct cert_arp_hdr *cah = (struct cert_arp_hdr *)
			rte_pktmbuf_append(new_buf, (uint16_t) sizeof(struct cert_arp_hdr));
		cah->cert_index = cert_index;
		cah->cert_total_count = cert_cnt;
		cah->cert_len = i2d_X509(cert, NULL);

		/* Digest message for signature. */
		unsigned char *message = rte_pktmbuf_mtod_offset(
			new_buf, unsigned char *, sizeof(struct rte_ether_hdr));
		size_t message_len = sizeof(struct rte_arp_hdr) + sizeof(struct cert_arp_hdr);
		unsigned char digest[SHA256_DIGEST_LENGTH];
    	SHA256(message, message_len, digest);

		/* Append the signature. */
		unsigned char *signature = (unsigned char *) malloc(RSA_size(rsa));
		unsigned int signature_len = 0;
		int result = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &signature_len, rsa);
		if (result != 1) {
			printf("failed to generate RSA signature.\n");
			free(signature);
			return;
		}
		cah->sig_len = (uint32_t) signature_len;
		memcpy((unsigned char *) rte_pktmbuf_append(new_buf, (uint16_t) signature_len), signature, signature_len);
		free(signature);
		
		/* Append the certificate. */
		cert_payload = (X509 *) rte_pktmbuf_append(new_buf, cah->cert_len);
		memcpy(cert_payload, cert, cah->cert_len);

		const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &new_buf, 1);
		if (unlikely(nb_tx < 1)) {
			printf("failed to transmit the %u-th reply packet.\n", cert_index);
			return 1;
		}
		else {
			sleep(1);
			printf("transmitted back the ARP reply (%u/%u).\n", cert_index, cert_cnt);
		}
	}
	return 0;
}

static inline int
format_ipv4_addr(uint32_t addr, char *s, uint32_t len)
{
	if (len < 16) {
		printf("ipv4 address char array should be longer than 16.\n");
		return 0;
	}
	int offset = 0;
	for (int i=0; i<4; ++i) {
		offset += sprintf(s + offset, "%d", addr & 0xff);
		addr >>= 8;
		if (i < 3) {
			offset += sprintf(s + offset, ".");
		}
	}
	return offset;
}

static inline int
get_fname(char *fname, uint32_t ip_addr, struct rte_ether_addr *eth_addr, uint16_t index)
{
	int flen;
	flen = format_ipv4_addr(ip_addr, fname, 16);
	fname[flen] = ' ';
	rte_ether_format_addr(fname + flen + 1, 18, eth_addr);
	flen += 1 + 17;
	sprintf(fname + flen, "_%u.der", index);
	return flen + 6;
}

static inline int
handle_arp_reply(
	struct rte_mempool *mbuf_pool,
	uint16_t port,
	struct rte_mbuf *buf,
	struct rte_ether_hdr *eh,
	struct rte_arp_hdr *ah,
	struct rte_ether_addr *eth_addr,
	uint32_t ip_addr)
{
	uint16_t offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct cert_arp_hdr *cah = rte_pktmbuf_mtod_offset(buf, struct cert_arp_hdr *, offset);
	offset += sizeof(struct cert_arp_hdr);
	uint16_t cert_len = buf->pkt_len - offset;
	if (cert_len != cah->cert_len) {
		printf("certificate length mismatch: %u (expected %u)\n", cert_len, cah->cert_len);
		return 1;
	}
	if (cah->cert_total_count > MAX_CERT_COUNT) {
		printf("certificate total count %u is greater than the maximum (%u)\n", cah->cert_total_count, MAX_CERT_COUNT);
		return 1;
	}
	if (cah->cert_total_count != CERT_COUNT) {
		printf("inconsistent cert_total_count: %u (expected=%u)\n", cah->cert_total_count, CERT_COUNT);
		return 1;
	}
	if (cah->cert_index >= cah->cert_total_count) {
		printf("invalid cert_index: %u (total=%u)\n", cah->cert_index, cah->cert_total_count);
		return 1;
	}

	/* Load signature and certificate. */
	unsigned char *signature = (unsigned char *) malloc(cah->sig_len);
	X509 *cert = (X509 *) malloc(cah->cert_len);
	memcpy(signature, rte_pktmbuf_mtod_offset(buf, void *, offset), cah->sig_len);
	memcpy(cert, rte_pktmbuf_mtod_offset(buf, void *, offset + cah->sig_len), cah->cert_len);
	
	printf("signature size: %u\n", cah->sig_len);
	printf("cert size: %u\n", cah->cert_len);
	printf("actual packet size: %u\n", buf->pkt_len);

	
	printf("cert size: %u\n", buf->pkt_len);
	
	/* File name of the certificate. */
	char fname[16+18+6];  // ip + ' ' + eth + '_' + index + ".der"
	get_fname(fname, ip_addr, eth_addr, cah->cert_index);

	/* Save certificate. */
	FILE *fp = fopen(fname, "w");
	printf("opend a file\n");
	if (!i2d_X509_fp(fp, cert)) {
		printf("failed to save %s\n", fname);
	}
	fclose(fp);
	free(cert);
	printf("saved a cert (%u/%u) to %s\n", cah->cert_index, cah->cert_total_count, fname);

	/* Check if all the certificates arrived. */
	for (uint16_t index=0; index<cah->cert_total_count; ++index) {
		get_fname(fname, ip_addr, eth_addr, index);
		if (access(fname, F_OK) != 0) {
			printf("%s is missing\n", fname);
			return 0;
		}
	}

	/* Verify ip-eth address in the certificate. */
	char command[100], result[100];
	get_fname(fname, ip_addr, eth_addr, cah->cert_total_count - 1);
	sprintf(command, "openssl x509 -noout -subject -in \"%s\"", fname);
	fp = popen(command, "r");
	fgets(result, 100, fp);  // subject=CN = xxx.xxx.xxx.xxx xx:xx:xx:xx:xx:xx
	pclose(fp);
	uint32_t n[4] = {0, 0, 0, 0}, j=0, cert_ip;
	struct rte_ether_addr cert_eth;
	int i;
	for (i=13; i<100; i++) {
		if (result[i] == '.') {
			j += 1;
		}
		else if (result[i] == ' ') {
			cert_ip = RTE_IPV4(n[3], n[2], n[1], n[0]);
			break;
		}
		else {
			n[j] *= 10;
			n[j] += result[i] - '0';
		}
	}
	rte_ether_unformat_addr(result+i+1, &cert_eth);
	if (cert_ip != ip_addr || !rte_is_same_ether_addr(eth_addr, &cert_eth)) {
		printf("ip and ethernet address pairs do not match.\n");
		return 1;
	}

	/* Convert the certificates to PEM. */
	for (uint16_t index=0; index<cah->cert_total_count; ++index) {
		int flen = get_fname(fname, ip_addr, eth_addr, index);
		int clen = sprintf(command, "openssl x509 -in \"%s\" -inform DER -out ", fname);
		fname[flen-4] = 0;
		sprintf(command + clen, "\"%s.crt\"", fname);
		if (system(command)) {
			printf("certificate conversion failed.\n");
			return 1;
		}
	}

	/* Verify the certificates. */
	int clen = sprintf(command, "openssl verify -CAfile ");
	for (uint16_t index=0; index<cah->cert_total_count; ++index) {
		int flen = get_fname(fname, ip_addr, eth_addr, index);
		fname[flen-4] = 0;
		clen += sprintf(command + clen, "\"%s.crt\" ", fname);
	}
	int retval = system(command);
	if (retval != 0) {
		printf("verification failed with code %d\n", retval);
		return retval;
	}

	printf("successfully verified!\n");
	
	return 0;
}

static inline int
handle_arp_packet(
	struct rte_mempool *mbuf_pool,
	uint16_t port,
	struct rte_mbuf *buf,
	uint32_t ip_addr,
	struct rte_ether_addr *eth_addr,
	X509 **certs,
	const uint16_t cert_cnt,
	RSA *rsa)
{
	struct rte_ether_hdr *eh;
	struct rte_arp_hdr *ah;
	struct rte_arp_ipv4 *ad;
	char *payload;
	char csha[20], ctha[20];
	uint16_t offset = 0;
	eh = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	offset += sizeof(struct rte_ether_hdr);
	ah = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *, offset);
	printf("arp_hardware: %x\n", rte_be_to_cpu_16(ah->arp_hardware));
	printf("arp_protocol: %x\n", rte_be_to_cpu_16(ah->arp_protocol));
	printf("arp_hlen: %d\n", ah->arp_hlen);
	printf("arp_plen: %d\n", ah->arp_plen);
	printf("arp_opcode: %x\n", rte_be_to_cpu_16(ah->arp_opcode));
	
	ad = &(ah->arp_data);
	rte_ether_format_addr(csha, 20, &(ad->arp_sha));
	printf("arp_sha: %s\n", csha);
	printf("arp_sip: %08x\n", ad->arp_sip);
	rte_ether_format_addr(ctha, 20, &(ad->arp_tha));
	printf("arp_tha: %s\n", ctha);
	printf("arp_tip: %08x\n", ad->arp_tip);
	
	/* Send back an ARP reply message for ARP requests.
		* See also: https://datatracker.ietf.org/doc/html/rfc826
		*/
	if (ah->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER)) {
		printf("unsupported hardware.\n");
		return 1;
	}

	if (ah->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		printf("unsupported protocol.\n");
		return 1;
	}

	/* Skip the ARP table update. */

	if (ah->arp_data.arp_tip != ip_addr) {
		printf("protocol address (IPv4) mismatch (!=%08x).\n", ip_addr);
		return 1;
	}
	
	/* Reveal the inner payload. */
	offset += sizeof(struct rte_arp_hdr);
	payload = rte_pktmbuf_mtod_offset(buf, char *, offset);
	// printf("payload: ");
	uint32_t len = buf->data_len - offset;
	// for (uint32_t c=0; c<len; ++c) {
	// 	printf("%c", payload[c]);
	// }
	// printf("\n  (hex): ");
	// for (uint32_t c=0; c<len; ++c) {
	// 	printf("%02x ", payload[c]);
	// }
	// printf("\n");

	if (ah->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
		if (port != 1) {
			printf("arp request is received in port %u (expected 0).\n", port);
			return 0;
		}
		return handle_arp_request(mbuf_pool, port, buf, eh, ah, eth_addr, ip_addr, certs, cert_cnt, rsa);
	}
	else if (ah->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
		if (port != 0) {
			printf("arp reply is received in port %u (expected 1).\n", port);
		}
		return handle_arp_reply(mbuf_pool, port, buf, eh, ah, &(ah->arp_data.arp_sha), ah->arp_data.arp_sip);
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static void
lcore_main(struct rte_mempool *mbuf_pool)
{
	struct rte_arp_hdr *ah;
	struct rte_arp_ipv4 *ad;
	struct rte_ether_hdr *eh;
	struct rte_ether_addr addr;
	struct rte_mbuf *bufs[BURST_SIZE];
	char caddr[20];
	char *payload;
	uint16_t port;
	int retval;
	const uint32_t ip_addr[2] = {IP_0, IP_1};
	const char *cert_paths[CERT_COUNT] = CERT_PATHS;
	X509 *certs[CERT_COUNT];
	RSA *rsa;
	FILE *fp;

	/* Load certificates. */
	for (int i; i<CERT_COUNT; ++i) {
		fp = fopen(cert_paths[i], "r");
		if (!fp) {
			printf("failed to load a certificate: %s\n", cert_paths[i]);
			return;
		}
		certs[i] = d2i_X509_fp(fp, NULL);
		fclose(fp);
	}
	printf("loaded %u certificates.\n", CERT_COUNT);

	/* Load the private key. */
	fp = fopen(KEY_PATH, "r");
	if (!fp) {
		printf("failed to open the private key %s\n", KEY_PATH);
		return;
	}
	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!rsa) {
		printf("failed to read the private key %s\n", KEY_PATH);
		return;
	}
	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Send an ARP request message from port 0 to port 1. */
	struct rte_arp_ipv4 _ad;
	if (rte_eth_macaddr_get(0, &addr) != 0) {
		printf("failed to get macaddr of port 0.\n");
		return;
	}
	_ad.arp_sha = addr;
	_ad.arp_sip = ip_addr[0];
	if (rte_eth_macaddr_get(1, &addr) != 0) {
		printf("failed to get macaddr of port 1.\n");
		return;
	}
	_ad.arp_tha = addr;
	_ad.arp_tip = ip_addr[1];
	if (send_arp_request(0, &_ad, mbuf_pool)) {
		printf("failed to send an ARP request.\n");
		return;
	}

	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			retval = rte_eth_macaddr_get(port, &addr);
			if (unlikely(retval)) {
				printf("could not get the ethernet MAC address of port %u.\n", port);
				continue;
			}
			for (int i=0; i<nb_rx; ++i) {
				eh = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

				/* Check if the packet is from one of the local ports. */
				const bool LOCAL_ONLY = true;
				if (LOCAL_ONLY) {
					uint16_t other_port;
					struct rte_ether_addr other_addr;
					bool is_local = false;
					RTE_ETH_FOREACH_DEV(other_port) {
						if (rte_eth_macaddr_get(other_port, &other_addr) != 0) {
							printf("failed to get mac address of port %u.\n", other_port);
							return;
						}
						if (rte_is_same_ether_addr(&eh->src_addr, &other_addr)) {
							is_local = true;
							break;
						}
					}
					if (!is_local) continue;
				}
				printf("\n%u packets received from %u.\n", nb_rx, port);
				rte_ether_format_addr(caddr, 20, &(eh->src_addr));
				printf("src: %s\n", caddr);
				rte_ether_format_addr(caddr, 20, &(eh->dst_addr));
				printf("dst: %s\n", caddr);
				printf("type: %x\n", rte_be_to_cpu_16(eh->ether_type));

				if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
					retval = handle_arp_packet(mbuf_pool, port, bufs[i], ip_addr[port], &addr, certs, CERT_COUNT, rsa);
					if (retval != 0) {
						printf("something is wrong: returned %d\n", retval);
						continue;
					}
				}
			}
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main(mbuf_pool);
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
