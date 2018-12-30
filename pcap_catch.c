#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<time.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>

int main(int argc,char **argv)
{
	char *filter = "";
	char *filename = "";
	int i;
	for(i=1;i<argc;i++){
		if(i == 1){
			filename = argv[1];
		}
		else{
			filter = argv[2];
		}
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(filename,errbuf);
	if(!handle) {
		printf("pcap file open error\n");
		return -1;
	}
	printf("Open %s success\n", filename);

	struct bpf_program filter_code;
	if(pcap_compile(handle,&filter_code,filter,1,PCAP_NETMASK_UNKNOWN) == -1) {
		printf("pcap file compile error\n");
		pcap_close(handle);
		return -1;
	}

	if(strlen(filter) != 0){
		printf("Filter: %s\n", filter);
	}
	FILE *fp = fopen("output.txt","w");
	if(!fp){
		printf("Output file open error\n");
	}
	while(1) {
		struct pcap_pkthdr *header = NULL;
		const u_char *content = NULL;
		int ret = pcap_next_ex(handle,&header,&content);
		if(ret == 1) {
			if(pcap_offline_filter(&filter_code,header,content) != 0) {
				fprintf(fp,"Pocket length : %d\n",header -> len);

				struct tm *now;
				now = localtime(&header -> ts.tv_sec);
				char buf[100];
				strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",now);
				fprintf(fp,"Time : %s\n",buf);
	
				struct ip *ip_header = (struct ip*)(content + 14);
				char source_ip[INET_ADDRSTRLEN];
				char destination_ip[INET_ADDRSTRLEN];
				u_char prot = ip_header -> ip_p;
				switch(prot){
					case IPPROTO_UDP:
						printf("UDP\n");
						struct udphdr *udp_header = (struct udphdr*)(content + 14 + (ip_header -> ip_hl << 2));
						u_int16_t source_port = ntohs(udp_header -> uh_sport);
						fprintf(fp,"Source port : %5u\n",source_port);
						u_int16_t destination_port = ntohs(udp_header -> uh_dport);
						fprintf(fp,"Destination port : %5u\n",destination_port);
						break;
					case IPPROTO_TCP:
						printf("TCP\n");
						struct tcphdr *tcp_header = (struct tcphdr*)(content + 14 + (ip_header -> ip_hl << 2));
						source_port = ntohs(tcp_header -> th_sport);
						fprintf(fp,"Source port : %5u\n",source_port);
						destination_port = ntohs(tcp_header -> th_dport);
						fprintf(fp,"Destination port : %5u\n",destination_port);
						break;
					default:
						printf("Next is %d\n",prot);
						break;
				}
				strcpy(source_ip,inet_ntoa(ip_header -> ip_src));
				strcpy(destination_ip,inet_ntoa(ip_header -> ip_dst));
				fprintf(fp,"Source IP : %s\n",source_ip);
				fprintf(fp,"Destination IP : %s\n",destination_ip);
			}
		}
		else if(ret == 0) {
			printf("Timeout\n");
		}
		else if(ret == -1) {
			printf("Catch next file error\n");
		}
		else if(ret == -2) {
			printf("No more packet from file\n");
			break;
		}
		fprintf(fp,"\n");
	}
	return 0;
}
