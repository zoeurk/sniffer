#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "others.h"
#include "utils.h"

#include "bootp.h"

const char *dhcp_message[] = {
	"DHCPDISCOVER",
	"DHCPOFFER",
	"DHCPREQUEST",
	"DHCPDECLINE",
	"DHCPACK",
	"DHCPNAK",
	"DHCPRELEASE",
	"DHCPINFORM"
};
const char *vendor_options[] = {
	NULL,
	"Subnet Mask", //1
	"Time Offset", //2
	"Router", //3
	"Time Server", //4
	"Name Server", //5
	"Domain Name Server", //6
	"Log Server",
	"Cookie Server",
	"LPR Server",
	"Impress Server",
	"Ressource Location",
	"Host Name",
	"Boot File Size",
	"Merit Dump File",
	"Domain Name",
	"Swap",
	"Root Path",
	"Extentions Path",
	"IP Forwarding",
	"Non-Local Source Routing",
	"Policy Filter",
	"Maximum Datagram Reassembly Size",
	"Default IP Time-To-Live",
	"Path MTU Aging Timeout",
	"Path MTU Plateau Table",
	"Interface MTU",
	"All Subnet Are Local",
	"Broadcast Address",
	"Perform Mask Discovery",
	"Mask Supplier",
	"Perform Router Discovery",
	"Router Solicitation Address",
	"Static Route",
	"Trailer Encapsulation",
	"ARP Cache Timeout",
	"Ethernet Encapsulation",
	"TCP default TTL",
	"TCP Keepalive Interval",
	"TCP Keepalive Garbage",
	"Network Information Service Domain",
	"Network Information Servers",
	"Network Time Protocol Servers",
	"Vendor Specific Information",
	"NetBIOS Over TCP/IP Name Server",
	"NetBIOS Over TCP/IP Datagram Distribution Server",
	"NetBIOS Over TCP/IP Node Type",
	"NetBIOS Over TCP/IP Scope",
	"X Window System Font Server", //48
	"X Window System Display Manager",//49
	"Requested IP Address", //50
	"IP Address Lease Time", //51
	"Option Overload", //52
	"DHCP Message Type",//53
	"Server Identifier",//54
	"Parameter Request List",//55
	"Message", //56
	"Maximum DHCP Message Size", //57
	"Renewal (T1) Time Value", //58
	"Rebinding (T2) Time Value", //59
	"Vendor Class Identifier", //60
	"Client-Identifier", //61
	NULL, //62
	NULL, //63
	"Network Information Service+ Domain", //64
	"Network Information Service+ Servers", //65
	"TFTP Server Name", //66
	"Bootfile Name", //67
	"Mobile IP Home Agent", //68
	"SMTP Server", //69
	"POP3 Server",  //70
	"NNTP Server",  //71
	"Default WWW Server", //72
	"Default Finger Server", //73
	"Default IRC Server",//74
	"StreetTalk Server", //75
	"STDA Server", //76
};
enum tag{
	Subnet_Mask = 1, //ok
	Time_Offset = 2, //ok
	Router = 3, //ok
	Time_Server = 4, //ok
	Name_Server = 5, //ok
	Domain_Name_Server = 6, //ok
	Log_Server = 7, //ok
	Cookie_Server = 8, //ok
	LPR_Server = 9, //ok
	Impress_Server = 10, //ok
	Ressource_Location = 11, //ok
	Host_Name = 12, //ok
	Boot_File_Size = 13, //ok
	Merit_Dump_File = 14, //ok
	Domain_Name = 15, //ok
	Swap = 16, //ok
	Root_Path = 17, //ok
	Extentions_Path = 18, //ok
	IP_Forwarding = 19, //ok
	NonLocal_Source_Routing = 20, //ok
	Policy_Filter = 21, //ok
	Maximum_Datagram_Reassembly_Size = 22, //ok
	Default_IP_TimeToLive = 23, //ok
	Path_MTU_Aging_Timeout = 24, //ok
	Path_MTU_Plateau_Table = 25, //ok
	Interface_MTU = 26, //ok
	All_Subnet_Are_Local = 27, //ok
	Broadcast_Address = 28, //ok
	Perform_Mask_Discovery = 29, //ok
	Mask_Supplier = 30, //ok
	Perform_Router_Discovery = 31, //ok
	Router_Solicitation_Address = 32, //ok
	Static_Route = 33, //ok
	Trailer_Encapsulation = 34, //ok
	ARP_Cache_Timeout = 35, //ok
	Ethernet_Encapsulation = 36, //ok
	TCP_default_TTL = 37, //ok
	TCP_Keepalive_Interval = 38, //ok
	TCP_Keepalive_Garbage = 39, //ok
	Network_Information_Service_Domain = 40, //ok
	Network_Information_Servers = 41, //ok
	Network_Time_Protocol_Servers = 42, //ok
	Vendor_Specific_Information = 43,
	NetBIOS_Over_TCPIP_Name_Server = 44, //ok
	NetBIOS_Over_TCPIP_Datagram_Distribution_Server = 45, //ok
	NetBIOS_Over_TCPIP_Node_Type = 46, //ok
	NetBIOS_Over_TCPIP_Scope = 47,
	X_Window_System_Font_Server = 48, //ok
	X_Window_System_Display_Manager = 49, //ok
	Requested_IP_Address = 50, //ok
	IP_Address_Lease_Time = 51, //ok
	Option_Overload = 52, //ok
	DHCP_Message_Type = 53, //ok
	Server_Identifier = 54, //ok
	Parameter_Request_List = 55, //ok
	Message = 56, //ok
	Maximum_DHCP_Message_Size = 57, //ok
	Renewal_T1_Time_Value = 58, //ok
	Rebinding_T2_Time_Value = 59, //ok
	Vendor_Class_Identifier = 60, 
	ClientIdentifier = 61, //ok
	Network_Information_ServicePlus_Domain = 64,
	Network_Information_ServicePlus_Servers = 65, //ok
	TFTP_Server_Name = 66, //pas sure
	Bootfile_Name = 67, //pas sure
	Mobile_IP_Home_Agent = 68, //pas sure
	SMTP_Server = 69, //ok
	POP3_Server = 70,  //ok
	NNTP_Server = 71, //ok
	Default_WWW_Server = 72, //ok
	Default_Finger_Server = 73, //ok
	Default_IRC_Server = 74, //ok
	StreetTalk_Server = 75, //ok
	STDA_Server = 76 //ok
};
void print_tag(unsigned char *vend, int len){
	struct sockaddr_in sa;
	unsigned long int __sa__ = sizeof(sa);
	int j, space = 1;
	char buf[16], *pbuf = buf, hostname[NI_MAXHOST], *h = hostname;
	memset(buf,0,16);
	for(j = 0;j < len; j++){
		//printf("%u",vend[j+1]);
		sprintf(pbuf,"%i",vend[j+1]);
		pbuf+=strlen(pbuf);
		if(j == len -1){
			if((args.options&NORESOLV) == 0 && ___getnameinfo___(&sa,__sa__, &h, NI_MAXHOST, buf) == 0)
				printf("%s", hostname);
			else	printf("%s", buf);
			//printf("%s",buf);
			printf("\n");
			space = 1;
		}else{
			if(space == 4){
				//printf("%s", buf);
				if((args.options&NORESOLV) == 0 && ___getnameinfo___(&sa,__sa__, &h, NI_MAXHOST, buf) == 0)
					printf("%s", hostname);
				else	printf("%s", buf);
				pbuf = buf;
				memset(buf,0,16);
				printf(" ");
				space = 1;
			}else{
				*pbuf = '.';
				pbuf++;
				//printf(".");
				space++;
			}
		}
	}
}
void print_addrmask(unsigned char *vend, int len){
	int j, space = 1;
	for(j = 0;j < len; j++){
		printf("%u",vend[j+1]);
		if(j == len -1){
			printf("\n");
			space = 1;
		}else{
			if(space == 4)printf(" Mask: ");
			if(space == 8){
				printf("\n\t\t");
				space = 1;
			}else{
				printf(".");
				space++;
			}
		}
	}
}
void print_router(unsigned char *vend, int len){
	int j, space = 1;
	for(j = 0;j < len; j++){
		printf("%u",vend[j+1]);
		if(j == len -1){
			printf("\n");
			space = 1;
		}else{
			if(space == 4)printf(" Router: ");
			if(space == 8){
				printf("\n\t\t");
				space = 1;
			}else{
				printf(".");
				space++;
			}
		}
	}
}
void service_dhcp(void *data, unsigned long int len){
	struct dhcp *d = (struct dhcp *)data;
	static unsigned char cookie[4] = MAGIC_COOKIE;
	struct in_addr s1,s2,s3,s4;
	char addr1[48],addr2[48],addr3[48],addr4[45];
	unsigned char *vend;
	int i, j, _len_, tag, occurs = 0;
	memcpy(&s1.s_addr,&d->ciaddr,sizeof(s1.s_addr));
	inet_ntop(AF_INET,&s1,addr1,sizeof(addr1));
	memcpy(&s2.s_addr,&d->yiaddr,sizeof(s2.s_addr));
	inet_ntop(AF_INET,&s2,addr2,sizeof(addr2));
	memcpy(&s3.s_addr,&d->siaddr,sizeof(s3.s_addr));
	inet_ntop(AF_INET,&s3,addr3,sizeof(addr3));
	memcpy(&s4.s_addr,&d->giaddr,sizeof(s4.s_addr));
	inet_ntop(AF_INET,&s4,addr4,sizeof(addr4));
	printf("\n\top: %u\n\tType: %u\n\tLen: %u\n\thops: %u\n\txid: 0x%08x\n\tsec: %u seconds\n\tFlags: %u\n\tciaddr: %s\n\tyiaddr: %s\n\tsiaddr: %s\n\tgiaddr: %s\n\tchaddr ",
	d->op,d->htype,d->hlen,d->hops,ntohl(d->xid),ntohs(d->secs),d->flags,addr1,addr2,addr3,addr4);
	for(i = 0; i < d->hlen;i++){
		printf("%02x",((char *)d->chaddr)[i]&0xFF);
		if((char)i < d->hlen -1)
			printf(":");
	}
	printf("\n\tsname: %s\n\tfile: %s\n",(char *)d->sname,(char *)d->file);
	if(memcmp(d->vend,cookie,sizeof(int)) == 0){
		vend = (unsigned char *)d->vend;
		printf("\tCookie: 0x%08x\n",*((int*)vend));
		vend += sizeof(int);
		for(i = 0;i< 256;i++,vend++)
		{	
			tag = *vend;
			printf("\t\tOption %i: ",tag);
			if(tag == 255){
				while(vend[1] == 0){
					occurs++;
					vend++;
				}
				printf("End Of Options\n\t\tPAD occurs: %i\n",occurs);
				/*for(i = 1; i < 73; i++){
					printf("%u ==> %s\n",i, vendor_options[i]);
				}*/
				return;
			}
			vend++;
			_len_ = *vend;
			switch(tag){
				case SMTP_Server: 
				case POP3_Server: 
				case NNTP_Server:
				case Default_WWW_Server:
				case Default_Finger_Server:
				case Default_IRC_Server:
				case StreetTalk_Server: 
				case STDA_Server:
				case Mobile_IP_Home_Agent:
				case Network_Information_ServicePlus_Servers:
				case Requested_IP_Address:
				case X_Window_System_Display_Manager:
				case X_Window_System_Font_Server:
				case NetBIOS_Over_TCPIP_Datagram_Distribution_Server:
				case NetBIOS_Over_TCPIP_Name_Server:
				case Network_Time_Protocol_Servers:
				case Network_Information_Servers:
				case Router_Solicitation_Address:
				case Broadcast_Address:
				case Server_Identifier:
				case Swap:
				case Router:
				case Time_Server:
				case Name_Server:
				case Domain_Name_Server:
				case Log_Server:
				case Cookie_Server:
				case LPR_Server:
				case Impress_Server:
				case Ressource_Location:
				case Subnet_Mask:
					printf("%s: ",vendor_options[tag]);
					print_tag(vend,_len_);
					break;
				case Rebinding_T2_Time_Value:
				case Renewal_T1_Time_Value:
				case TCP_Keepalive_Interval:
				case ARP_Cache_Timeout:
				case Path_MTU_Aging_Timeout:
				case IP_Address_Lease_Time:
				case Time_Offset:
					printf("%s: %u\n",vendor_options[tag],ntohl(((unsigned int *)&vend[1])[0]));
					break;
				case Bootfile_Name:
				case TFTP_Server_Name:
				case Message:
				case Network_Information_Service_Domain:
				case Extentions_Path:
				case Host_Name:
				case Merit_Dump_File:
				case Domain_Name:
				case Root_Path:
					printf("%s: ",vendor_options[tag]);
					for(j = 1; j <= _len_; j++){
						printf("%c",vend[j]);
					}
					printf("\n");
					break;
				case Maximum_DHCP_Message_Size:
				case Interface_MTU:
				case Maximum_Datagram_Reassembly_Size:
				case Boot_File_Size:
					printf("%s: %u\n",vendor_options[tag],ntohs((((unsigned short int *)&vend[1])[0])));
					break;
				case DHCP_Message_Type:
					printf("%s: %s\n", vendor_options[tag], dhcp_message[vend[1]-1]);
					break;
				case TCP_Keepalive_Garbage:
				case TCP_default_TTL:
				case Ethernet_Encapsulation:
				case Trailer_Encapsulation:
				case Perform_Router_Discovery:
				case Mask_Supplier:
				case Perform_Mask_Discovery:
				case All_Subnet_Are_Local:
				case NonLocal_Source_Routing:
				case IP_Forwarding:
				case Default_IP_TimeToLive:
					printf("%s: %u\n",vendor_options[tag],vend[1]);
					break;
				case Parameter_Request_List:
					printf("\n");
					for(j = 1; j < _len_ && j < 77; j++){
						printf("\t\t\t%s\n",vendor_options[j]);
					}
					break;
				case ClientIdentifier:
					printf("Hardware: %u: ", vend[1]);
					for(j = 0; j < _len_-1;j++){
						printf("%02x",vend[2+j]&0xFF);
						if(j < _len_-2)
							printf(":");
						else
							printf("\n");
					}
					break;
				case Policy_Filter:
					printf("%s:\n\t\t",vendor_options[tag]);
					print_addrmask(vend,_len_);
					break;
				case Path_MTU_Plateau_Table:
					for(j = 0; j < _len_; j+=2)
						printf("\n\t\t%s: %u",vendor_options[tag],ntohs((((unsigned short int *)&vend[1])[j/2])));
					printf("\n");
					break;
				case Static_Route:
					printf("%s:\n\t\t",vendor_options[tag]);
					print_router(vend,_len_);
					break;
				case NetBIOS_Over_TCPIP_Node_Type:
					printf("%s: ",vendor_options[tag]);
					switch(vend[1])
					{
						case 1: printf("B-node\n");
							break;
						case 2: printf("P-node\n");
							break;
						case 4: printf("M-node\n");
							break;
						case 8: printf("H-node\n");
							break;
					}
					break;
				case Option_Overload:
					printf("%s: ",vendor_options[tag]);
					switch(vend[1])
					{
						case 1: printf("\'file\' field is used\n");
							break;
						case 2: printf("\'sname\' field is used\n");
							break;
						case 3: printf("both \'file\' and \'sname\' fileds are used\n");
							break;
					}
					break;
				default:
					printf("unknow\n");
					//print_tag(&vend[1],_len_);
					break;
			}
			vend += _len_;
		}
	}
}
