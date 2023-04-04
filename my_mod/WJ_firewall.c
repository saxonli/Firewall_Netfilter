//#define __KERNEL__
//#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/inet.h>
#include "sha256.h"

#include <linux/random.h>
#include <linux/slab.h>

#define MATCH	1
#define NMATCH	0

#define LOCAL_IP_LEN 2

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
unsigned int controlled_time_flag = 0;
unsigned int controlled_time_begin = 0;
unsigned int controlled_time_end = 0;

char ip_buff_src[16];
char ip_buff_dst[16];
char port_buff_src[10];
char port_buff_dst[10];
char time_buff[50];
char protocol_buff[10];

char controlinfo[64000]; //存储多条规则，每条32byte
char *pchar; // pchar 为指向 controlinfo 的以 位 为单位的指针
int num = 0; //规则条数

struct sk_buff *tmpskb;
struct iphdr *piphdr;

char local_pre_hc[65];
char sha256_str[65];

/**
 * @func: sha256哈希函数
 * @desc: sha256接口
 * @param: {str:需要计算哈希值的字符串}  
 * @return: {NULL} 
 */
void sha256(char *str)
{
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int i;
	
	memset(&ctx, 0, sizeof(ctx));
    memset(buf, 0, SHA256_BLOCK_SIZE);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, str, strlen((const char *)str));
	SHA256_Final(&ctx, buf);
	for(i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        sprintf(sha256_str+i*2,"%02x",buf[i]);
    }
}

// Deception 模块
#define DEFAULT_TTL 64 // 路由器默认的初始 TTL 值
#define DECEPTION_IP_MAX_NUM 60 // config 文件一行 IP 的最大数目
#define DECEPTION_MAXHOP 4 // config 中的最大 TTL，注意和下面 unsigned int 型一样
__u8 preserve_ttl;
const unsigned int deception_maxhop = 4; // config 中的最大 TTL
__be32 preserve_saddr;
char deception_ip_line[DECEPTION_MAXHOP][1024]={
	"192.168.1.3 192.168.10.3 192.168.11.3 ",
	"192.168.2.3 192.168.12.3 192.168.13.3 ",
	"192.168.6.3 192.168.3.3 ",
	"192.168.5.3 192.168.4.3 "
};

char* generate_token(void) 
{
	int i;
    char* token = kmalloc(7, GFP_KERNEL);  // 为令牌分配7个字符的空间，包括字符串结束符'\0'
    if (token == NULL) {  // 内存分配失败
        return NULL;
    }
    get_random_bytes(token, 6);  // 生成6个随机字节
    for (i = 0; i < 6; i++) {
        int num = (int)(token[i]) % 36;  // 将随机字节转换为0到35之间的整数
        if (num < 10) {  // 将随机整数转换为数字或大写字母
            token[i] = num + '0';  // '0'的ASCII码为48，加上随机整数得到数字字符的ASCII码
        } else {
            token[i] = num + 55;  // 'A'的ASCII码为65，加上随机整数得到大写字母字符的ASCII码
        }
    }
    token[6] = '\0';  // 添加字符串结束符
    return token;
}

/**
 * @func: 随机数生成函数
 * @desc: 用于生成一个随机数
 * @param: {NULL}  
 * @return: {一个int型随机数} 
 */
// void get_random_bytes(void *buf, int nbytes);
static int my_rand(void)
{
	unsigned long randNum[9];
	int random_num=0;
	int i = 0;
	for (i=0; i<9; i++)
	{
		get_random_bytes(&randNum[i], sizeof(unsigned long));
		random_num = random_num * 10 + randNum[i];
	}
	return random_num;
}

/**
 * @func: 按行读取文件
 * @desc: 按行读取文件的自定义实现
 * @param: {buf:接受读取内容的缓冲区; max_size:读取的最大容量; fp:需打开的文件描述符}  
 * @return: {包含读取内容的缓冲区} 
 */
char *kernel_fgets(char *buf, int max_size, struct file *fp)
{
    int i = 0;
    int read_size;

    if(0 > max_size)
    {
        printk(KERN_EMERG "read max_size invalid\n");
        return NULL;
    }

    read_size = vfs_read(fp, buf, max_size, &(fp->f_pos));
    if(1 > read_size)
    {
        return NULL;
    }

    while(buf[i++] != '\n' && i < read_size);
    buf[i-1] = '\0';
    fp->f_pos += i-read_size;
    return buf;
}

/**
 * @func: IP地址整型
 * @desc: 将网络IP地址格式化为字符串
 * @param: {buff:转换后的char*类型的IP地址; addr:网络IP地址}  
 * @return: {buff:转换后的char*类型的IP地址} 
 */
char * addr_from_net(char * buff, __be32 addr)
{
    __u8 *p = (__u8*)&addr;
    snprintf(buff, 16, "%u.%u.%u.%u",
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}

/**
 * @func: 时间信息整型
 * @desc: 将struct rtc_time结构体中的时间信息格式化成字符串
 * @param: {buff:转换后的char*类型的时间信息; tm:struct rtc_time结构体中的时间信息}  
 * @return: {buff:转换后的char*类型的时间信息} 
 */
char * time_from_tm(char * buff, struct rtc_time *tm)
{
    snprintf(buff, 50, "%04d/%02d/%02d %02d:%02d:%02d",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buff;
}

/**
 * @func: 检查当前规则是否在有效过滤的时间内
 * @desc: 结果为1表示不在过滤时间内，为0表示在过滤时间内
 * @param: {tm:当前时间信息}  
 * @return: {结果为1表示不在过滤时间内，为0表示在过滤时间内} 
 */
bool cktime(struct rtc_time *tm) 
{
	//Time_Flag关闭，直接判断下一条规则
	if(controlled_time_flag == 0){ 
		return 0;
	}
	//Time_Flag开启，判断时间区间
	if(controlled_time_flag == 1){
		if(((tm->tm_hour*60+tm->tm_min)<controlled_time_begin)||((tm->tm_hour*60+tm->tm_min)>controlled_time_end))
		{
			return 1;
		}
		else return 0;
	}
	return 0;
}

/**
 * @func: 校验和计算函数
 * @desc: 通用的一种校验和计算函数
 * @param: {}  
 * @return: {} 
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);             /* add carry */
	answer = ~sum;              /* truncate to 16 bits */
	return (answer);
}

/**
 * @func: 端口匹配函数
 * @desc: 判断网络包的端口信息是否与当前规则匹配
 * @param: {srcport:网络包源端口; dstport:网络包目的端口}  
 * @return: {MATCH/NMATCH} 
 */
bool port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
	{
		return MATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport) return MATCH;
		else return NMATCH;
	}
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport) return MATCH;
		else return NMATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport)) return MATCH;
		else return NMATCH;
	}
	return NMATCH;
}

/**
 * @func: IP地址匹配函数
 * @desc: 判断网络包的IP地址信息是否与当前规则匹配
 * @param: {saddr:网络包源IP地址; daddr:网络包目的IP地址}  
 * @return: {MATCH/NMATCH} 
 */
bool ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
	{
		return MATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr) return MATCH;
		else return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr) return MATCH;
		else return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr)) return MATCH;
		else return NMATCH;
	}
	return NMATCH;
}

/**
 * @func: ICMP包检查
 * @desc: 检查当前ICMP包是否与某黑名单规则匹配
 * @param: {NULL}  
 * @return: {1:匹配; 0:不匹配} 
 */
bool icmp_check(void){
	struct icmphdr *picmphdr;
	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));
	if (picmphdr->type == 0){
			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return 1;
			}
	}
	if (picmphdr->type == 8){
			if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return 1;
			}
	}
    return 0;
}

/**
 * @func: TCP包检查
 * @desc: 检查当前TCP包是否与某黑名单规则匹配
 * @param: {NULL}  
 * @return: {1:匹配; 0:不匹配} 
 */
bool tcp_check(void){
	struct tcphdr *ptcphdr;
	ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	printk("A TCP packet is denied! \n");
	 	snprintf(port_buff_src, 10, ":%d", ntohs(ptcphdr->source));
        snprintf(port_buff_dst, 10, ":%d", ntohs(ptcphdr->dest));
		return 1;
	}
	else return 0;
}

/**
 * @func: UDP包检查
 * @desc: 检查当前UDP包是否与某黑名单规则匹配
 * @param: {NULL}  
 * @return: {1:匹配; 0:不匹配} 
 */
bool udp_check(void){
	struct udphdr *pudphdr;
	pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
	 	snprintf(port_buff_src, 10, ":%d", ntohs(pudphdr->source));
        snprintf(port_buff_dst, 10, ":%d", ntohs(pudphdr->dest));
	 	printk("A UDP packet is denied! \n");
		return 1;
	}
	else return 0;
}

/**
 * @func: NF_INET_PRE_ROUTING钩子函数
 * @desc: 实现可信过滤模块及网络欺骗与混淆模块的部分功能
 * @param: {}  
 * @return: {NF_ACCEPT/NF_DROP} 
 */
unsigned int pre_routing_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	struct timex txc;
	struct rtc_time tm;
	int udp_dport;
	int udp_data_len;
	char *udp_data_start;

   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);// IP 层包头获取

	//时间
	do_gettimeofday(&txc.time);   //获取当前UTC时间
    txc.time.tv_sec += 8 * 60 * 60;  //把UTC时间调整为本地时间
    rtc_time_to_tm(txc.time.tv_sec, &tm);   //算出时间中的年月日等数值到tm中
	time_from_tm(time_buff, &tm);

	// ==========可信过滤模块 + Intellgent Deception 模块==========
	if(piphdr->protocol  == 17) // UDP packet
	{
		struct udphdr *pudphdr;	// UDP 头部
		pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
		udp_dport = ntohs(pudphdr->dest);
		if(udp_dport < 33434 || udp_dport > 33534) // 不是 Traceroute packet
		{
			return NF_ACCEPT;
		}

		// ==========针对 Traceroute 探测包的 可信逻辑 处理==========
		// 获取可信包的 trustmethod 字段，判断可信过滤方式
		udp_data_len=ntohs(piphdr->tot_len)-piphdr->ihl*4-sizeof(struct udphdr);
		char udp_data[udp_data_len+1];
		// printk("<WJ>udp_data_len: %d\n",udp_data_len);
		if(udp_data_len > 0)
		{
			// 协议
			snprintf(protocol_buff, 10, "%s", "UDP");
			// 时间
			do_gettimeofday(&txc.time);   //获取当前UTC时间
			txc.time.tv_sec += 8 * 60 * 60;  //把UTC时间调整为本地时间
			rtc_time_to_tm(txc.time.tv_sec, &tm);   //算出时间中的年月日等数值到tm中
			time_from_tm(time_buff, &tm);
			// 地址
			addr_from_net(ip_buff_src, piphdr->saddr);
			addr_from_net(ip_buff_dst, piphdr->daddr);
			// 端口
			snprintf(port_buff_src, 10, ":%d", ntohs(pudphdr->source));
        	snprintf(port_buff_dst, 10, ":%d", ntohs(pudphdr->dest));

			udp_data_start=(char *)pudphdr+sizeof(struct udphdr);
			memset(udp_data,0,sizeof(udp_data));
			strncpy(udp_data,udp_data_start,udp_data_len);
			// printk("<WJ>udp_data: %s\n",udp_data);

			char trustmethod=udp_data[0];
			if(trustmethod == '1')// 可信 IP 处理
			{
				int i;
				pchar = controlinfo; 
				for (i = 0; i<num; i++)
				{
					controlled_protocol = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_saddr = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_daddr = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_srcport = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_dstport = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_time_flag = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_time_begin = *(( int *) pchar);
					pchar = pchar + 4;
					controlled_time_end = *(( int *) pchar);
					pchar = pchar + 4;

					// 判断该条规则是否在运行时间中，1:不在运行时间中；0:无flag或在运行时间中
					if(cktime(&tm) == 1){
						continue;
					}
					
					if(controlled_protocol == 117) // 该条规则是关于 UDP 的白名单规则
					{
						bool result = udp_check();
						if(result==1) // 源 IP 可信
						{
							return NF_ACCEPT;
						}
					}
				}
				printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
									time_buff, protocol_buff, ip_buff_src, port_buff_src,
									ip_buff_dst, port_buff_dst);
				return NF_DROP;
			}
			else if(trustmethod == '2')// 公钥签名认证
			{
				// // identification
				// char identification[5];
				// memset(identification,0,sizeof identification);
				// strncpy(identification,udp_data_start+1,4);

				// // 当前包的 message
				// char cur_message[65];
				// memset(cur_message,0,sizeof cur_message);
				// strncpy(cur_message,udp_data_start+5,64);
				// // printk("<WJ>message:%s\n",cur_message);

				// int ret;
				// ret = check_rsa_valid(cur_message);
				// if(ret == 1)
				// {
				// 	return NF_ACCEPT;
				// }
				// else
				// {
				// 	printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
				// 					time_buff, protocol_buff, ip_buff_src, port_buff_src,
				// 					ip_buff_dst, port_buff_dst);
				// 	return NF_DROP;
				// }


			}
			else if(trustmethod == '3')// 哈希链签名认证
			{
				if(piphdr->ttl == 1)
				{
					return NF_ACCEPT;
				}	
				// identification
				// char identification[5];
				// memset(identification,0,sizeof identification);
				// strncpy(identification,udp_data_start+1,4);

				// 当前包的 message
				char cur_message[65];
				memset(cur_message,0,sizeof cur_message);
				strncpy(cur_message,udp_data_start+5,64);
				// printk("<WJ>cur_message:%s\n",cur_message);

				// 当前包的 hc
				char cur_hc[65];
				memset(cur_hc,0,sizeof cur_hc);
				strncpy(cur_hc,udp_data_start+69,64);
				// printk("<WJ>cur_hc:%s\n",cur_hc);

				// base of local hc
				char base[129];
				memset(base,0,sizeof base);

				// h(message)
				memset(sha256_str,0,sizeof sha256_str);
				sha256(cur_message);
				// printk("<WJ>h(message):%s\n",sha256_str);
				strncat(base,sha256_str,64);
				
				// local pre_hc
				// printk("<WJ>pre_hc:%s\n",local_pre_hc);
				strncat(base,local_pre_hc,64);

				// local hc
				memset(sha256_str,0,sizeof sha256_str);
				sha256(base);
				// printk("<WJ>local hc is:%s\n",sha256_str);

				if(strncmp(sha256_str,cur_hc,64) == 0)
				{
					// trust_id = trust_id + 1;
					strncpy(local_pre_hc,cur_hc,64);
					return NF_ACCEPT;
				}
				else
				{
					printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
									time_buff, protocol_buff, ip_buff_src, port_buff_src,
									ip_buff_dst, port_buff_dst);
					return NF_DROP;
				}
			}
		}
	}

	return NF_ACCEPT;
}

/**
 * @func: NF_INET_POST_ROUTING钩子函数
 * @desc: 实现恶意探测检测与阻断模块及网络拓扑欺骗与混淆模块部分功能
 * @param: {}  
 * @return: {NF_ACCEPT/NF_DROP} 
 */
unsigned int post_routing_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	bool result = 0;
	struct timex txc;
	struct rtc_time tm;
	int udp_data_len;

   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);// IP 层包头获取

	//时间
	do_gettimeofday(&txc.time);   //获取当前UTC时间
    txc.time.tv_sec += 8 * 60 * 60;  //把UTC时间调整为本地时间
    rtc_time_to_tm(txc.time.tv_sec, &tm);   //算出时间中的年月日等数值到tm中
	time_from_tm(time_buff, &tm);

	addr_from_net(ip_buff_src, piphdr->saddr);
	addr_from_net(ip_buff_dst, piphdr->daddr);


	// ==========可信数据包处理==========
	if(piphdr->protocol  == 17)
	{ 

		struct udphdr *pudphdr;	// UDP 头部
		pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
		snprintf(protocol_buff, 10, "%s", "UDP");
		snprintf(port_buff_src, 10, ":%d", ntohs(pudphdr->source));
        snprintf(port_buff_dst, 10, ":%d", ntohs(pudphdr->dest));

		udp_data_len=ntohs(piphdr->tot_len)-piphdr->ihl*4-sizeof(struct udphdr);
		// printk("<WJ>udp_data_len: %d\n",udp_data_len);
		if(udp_data_len > 0)
		{
			char *udp_data_start=(char *)pudphdr+sizeof(struct udphdr);
			char trust_flag;
			trust_flag=udp_data_start[0];
			// printk("<WJ>trust_flag:%c \n",trust_flag);
			if(trust_flag == '1') 
			{
				printk("<WJ>%s  %s packet from  %s%s  to  %s%s  accept by TRUST IP\n",
							time_buff, protocol_buff, ip_buff_src, port_buff_src,
							ip_buff_dst, port_buff_dst);
				return NF_ACCEPT;
			}
			else if(trust_flag == '2') 
			{
				printk("<WJ>%s  %s packet from  %s%s  to  %s%s  accept by PUB KEY\n",
							time_buff, protocol_buff, ip_buff_src, port_buff_src,
							ip_buff_dst, port_buff_dst);
				return NF_ACCEPT;
			}
			else if(trust_flag == '3') 
			{
				printk("<WJ>%s  %s packet from  %s%s  to  %s%s  accept by HASH CHAIN\n",
							time_buff, protocol_buff, ip_buff_src, port_buff_src,
							ip_buff_dst, port_buff_dst);
				return NF_ACCEPT;
			}
		}
	}

	// 黑名单处理
	if(num == 0) return NF_ACCEPT; // write_controlinfo 中计算过规则条数
	else 
	{
		int i;
		pchar = controlinfo; // pchar 为指向 controlinfo 的以 位 为单位的指针
		for (i = 0; i < num; i++){
			// One rule，获取一条已存储的规则
			controlled_protocol = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_saddr = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_daddr = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_srcport = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_dstport = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_time_flag = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_time_begin = *(( int *) pchar);
			pchar = pchar + 4;
			controlled_time_end = *(( int *) pchar);
			pchar = pchar + 4;

			// 判断该条规则是否在运行时间中，1:不在运行时间中；0:无flag或在运行时间中
			if(cktime(&tm) == 1){
				continue;
			}

			if(piphdr->protocol != controlled_protocol) // 当前包未命中 controlinfo 本条规则的协议字段
			{ 
				result = 0; 
				continue; 
			}
			else
			{
				if (piphdr->protocol  == 1){ //ICMP packet
					snprintf(protocol_buff, 10, "%s", "ICMP");
					snprintf(port_buff_src, 10, " ");
					snprintf(port_buff_dst, 10, " ");
					result = icmp_check();
				}  
				else if (piphdr->protocol  == 6){ //TCP packet
					snprintf(protocol_buff, 10, "%s", "TCP");
					result = tcp_check();
				} 
				else if (piphdr->protocol  == 17){ //UDP packet
					snprintf(protocol_buff, 10, "%s", "UDP");
					result = udp_check();
				}
				else
				{
					printk("Unkonwn type's packet! \n");
					return NF_ACCEPT;
				}

				//Judge
				if(result == 0) continue;// 未命中黑名单的本条规则
				else {// 命中了黑名单的本条规则，丢弃数据包
					printk("<WJ>%s  %s packet from  %s%s  to  %s%s  rejected by rule %d \n",
						time_buff, protocol_buff, ip_buff_src, port_buff_src,
						ip_buff_dst, port_buff_dst, i+1);
					return NF_DROP;
				}
			}
		}
		return NF_ACCEPT;
	}
}

/**
 * @func: 从用户态读取规则
 * @desc: 从用户态读取规则
 * @param: {fd:向文件描述符指针; buf:指向用户空间缓冲区的指针; len:缓冲区长度; ppos:偏移量指针}  
 * @return: {缓冲区长度} 
 */
static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	if (len == 0)
	{
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0)
	{
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}

	pchar = controlinfo;
	num = len/32; // 计算规则条数
	
	return len;
}

// 向内核注册字符设备驱动fops
struct file_operations fops = {
	.owner=THIS_MODULE, 
	.write=write_controlinfo, // 写操作的回调函数为write_controlinfo
}; 

/**
 * @func: 读取哈希链文件
 * @desc: 初始化哈希链信息
 * @param: {NULL}  
 * @return: {NULL} 
 */
struct file *fp_hashchain;
mm_segment_t fs;
void read_hashchain(void)
{
	fp_hashchain = filp_open("/home/saxon/桌面/Firewal_Netfilter_Reconstruction/data/hashchain.txt",O_RDWR | O_CREAT,0644); // 注意是绝对路径
	if(IS_ERR(fp_hashchain))
	{
		printk("<WJ>Error!opening file hashchain,code: %d\n",(int)PTR_ERR(fp_hashchain));
	}
	else
	{
		fs=get_fs();
		set_fs(KERNEL_DS);
		if(kernel_fgets(local_pre_hc,65,fp_hashchain)==NULL)
		{
			printk("Error!reading failed\n");
			filp_close(fp_hashchain,NULL);
		}
		// printk("<WJ>%s\n",local_pre_hc);
		filp_close(fp_hashchain,NULL);
		set_fs(fs);
	}
}

/**
 * @func: 写入哈希链文件
 * @desc: 持久化哈希链信息
 * @param: {NULL}  
 * @return: {NULL} 
 */
void write_hashchain(void)
{
	fp_hashchain = filp_open("/home/saxon/桌面/Firewal_Netfilter_Reconstruction/data/hashchain.txt",O_RDWR | O_CREAT,0644); // 注意是绝对路径
	if(IS_ERR(fp_hashchain))
	{
		printk("<WJ>Error!opening file hashchain,code: %d\n",(int)PTR_ERR(fp_hashchain));
	}
	else
	{
		fs=get_fs();
		set_fs(KERNEL_DS);
		vfs_write(fp_hashchain,local_pre_hc,strlen(local_pre_hc),&(fp_hashchain->f_pos));
		filp_close(fp_hashchain,NULL);
		set_fs(fs);
	}
}

// NF_INET_PRE_ROUTING
static struct nf_hook_ops pre_routing_hook = {
   .hook = pre_routing_hook_func,
   .hooknum = NF_INET_PRE_ROUTING,
   .pf = PF_INET,
   .priority = NF_IP_PRI_FIRST,
};

// NF_INET_POST_ROUTING
static struct nf_hook_ops post_routing_hook = {
   .hook = post_routing_hook_func,
   .hooknum = NF_INET_POST_ROUTING,
   .pf = PF_INET,
   .priority = NF_IP_PRI_FIRST,
};

/**
 * @func: 内核注册函数
 */
static int __init initmodule(void)
{
	int ret;

	read_hashchain();

	nf_register_net_hook(&init_net,&pre_routing_hook);
	nf_register_net_hook(&init_net,&post_routing_hook);

	ret = register_chrdev(124, "/dev/controlinfo", &fops); 	
	if (ret != 0) printk("Can't register device file! \n");
	
    return 0;
}

/**
 * @func: 内核退出函数
 */
static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&pre_routing_hook);
	nf_unregister_net_hook(&init_net,&post_routing_hook);
	unregister_chrdev(124, "controlinfo");
	write_hashchain();
    printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("saxon");
