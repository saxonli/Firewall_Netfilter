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
#include <linux/delay.h>

#include "include/sha256.h"

#define MATCH	1
#define NMATCH	0

// 随机生成 IPV4 地址
#define OTHER_ERROR -1	//其它错误
#define LEGAL_IP 0		//合法IP
#define ILLEGAL_LEN 1	//IP长度不合法
#define INTERNEL_NET_IP 2	//属于内网IP

// 钩子定义
struct nf_hook_ops myhook_pre_routing;
struct nf_hook_ops myhook_local_in;
struct nf_hook_ops myhook_local_out;
struct nf_hook_ops myhook_post_routing;

//保存正在使用规则的信息
unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

unsigned int controlled_time_flag = 0;
unsigned int controlled_time_begin = 0;
unsigned int controlled_time_end = 0;

//正在处理数据包信息转化为字符串用于日志输出
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

// Random Deception 模块
char last_ip[16];// 用于记录上一个真实的 src_ip
char ip[16];// 用于记录随机生成的 src_ip

// Intelligent Deception 模块
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

// hashchain
char local_pre_hc[65];

/*    sha256 接口    */
char sha256_str[65];
void sha256(char *str)
{
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	memset(&ctx, 0, sizeof(ctx));
    memset(buf, 0, SHA256_BLOCK_SIZE);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, str, strlen((const char *)str));
	SHA256_Final(&ctx, buf);
	int i;
	for(i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        sprintf(sha256_str+i*2,"%02x",buf[i]);
    }
}

// // sha256 - begin
// #define SHA256_BLOCK_SIZE 32

// typedef unsigned char BYTE;
// typedef unsigned int  WORD;

// typedef struct {
// 	BYTE ctxdata[64];
// 	WORD datalen;
// 	unsigned long long bitlen;
// 	WORD state[8];
// } SHA256_CTX;

// void SHA256_Init(SHA256_CTX *ctx);
// void SHA256_Update(SHA256_CTX *ctx, const BYTE data[], WORD len);
// void SHA256_Final(SHA256_CTX *ctx, BYTE hash[]);

// #define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
// #define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
// #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
// #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
// #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
// #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
// #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// static const WORD k[64] = {
// 	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
// 	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
// 	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
// 	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
// 	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
// 	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
// 	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
// 	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
// };

// void sha256_transform(SHA256_CTX *ctx, const BYTE databuf[])
// {
// 	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

// 	for (i = 0, j = 0; i < 16; ++i, j += 4)
// 		m[i] = (databuf[j] << 24) | (databuf[j + 1] << 16) | (databuf[j + 2] << 8) | (databuf[j + 3]);
// 	for ( ; i < 64; ++i)
// 		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

// 	a = ctx->state[0];
// 	b = ctx->state[1];
// 	c = ctx->state[2];
// 	d = ctx->state[3];
// 	e = ctx->state[4];
// 	f = ctx->state[5];
// 	g = ctx->state[6];
// 	h = ctx->state[7];

// 	for (i = 0; i < 64; ++i) {
// 		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
// 		t2 = EP0(a) + MAJ(a,b,c);
// 		h = g;
// 		g = f;
// 		f = e;
// 		e = d + t1;
// 		d = c;
// 		c = b;
// 		b = a;
// 		a = t1 + t2;
// 	}

// 	ctx->state[0] += a;
// 	ctx->state[1] += b;
// 	ctx->state[2] += c;
// 	ctx->state[3] += d;
// 	ctx->state[4] += e;
// 	ctx->state[5] += f;
// 	ctx->state[6] += g;
// 	ctx->state[7] += h;
// }

// void SHA256_Init(SHA256_CTX *ctx)
// {
// 	ctx->datalen = 0;
// 	ctx->bitlen = 0;
// 	ctx->state[0] = 0x6a09e667;
// 	ctx->state[1] = 0xbb67ae85;
// 	ctx->state[2] = 0x3c6ef372;
// 	ctx->state[3] = 0xa54ff53a;
// 	ctx->state[4] = 0x510e527f;
// 	ctx->state[5] = 0x9b05688c;
// 	ctx->state[6] = 0x1f83d9ab;
// 	ctx->state[7] = 0x5be0cd19;
// }

// void SHA256_Update(SHA256_CTX *ctx, const BYTE databuf[], WORD len)
// {
// 	WORD i;

// 	for (i = 0; i < len; ++i) {
// 		ctx->ctxdata[ctx->datalen] = databuf[i];
// 		ctx->datalen++;
// 		if (ctx->datalen == 64) {
// 			sha256_transform(ctx, ctx->ctxdata);
// 			ctx->bitlen += 512;
// 			ctx->datalen = 0;
// 		}
// 	}
// }

// void SHA256_Final(SHA256_CTX *ctx, BYTE hash[])
// {
// 	WORD i;

// 	i = ctx->datalen;

// 	if (ctx->datalen < 56) {
// 		ctx->ctxdata[i++] = 0x80;  // pad 10000000 = 0x80
// 		while (i < 56)
// 			ctx->ctxdata[i++] = 0x00;
// 	}
// 	else {
// 		ctx->ctxdata[i++] = 0x80;
// 		while (i < 64)
// 			ctx->ctxdata[i++] = 0x00;
// 		sha256_transform(ctx, ctx->ctxdata);
// 		memset(ctx->ctxdata, 0, 56);
// 	}

// 	ctx->bitlen += ctx->datalen * 8;
// 	ctx->ctxdata[63] = ctx->bitlen;
// 	ctx->ctxdata[62] = ctx->bitlen >> 8;
// 	ctx->ctxdata[61] = ctx->bitlen >> 16;
// 	ctx->ctxdata[60] = ctx->bitlen >> 24;
// 	ctx->ctxdata[59] = ctx->bitlen >> 32;
// 	ctx->ctxdata[58] = ctx->bitlen >> 40;
// 	ctx->ctxdata[57] = ctx->bitlen >> 48;
// 	ctx->ctxdata[56] = ctx->bitlen >> 56;
// 	sha256_transform(ctx, ctx->ctxdata);

// 	for (i = 0; i < 4; ++i) {
// 		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
// 		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
// 	}

// }

// // sha256 接口
// char sha256_str[65];
// void sha256(char *str)
// {
// 	BYTE buf[SHA256_BLOCK_SIZE];
// 	SHA256_CTX ctx;
// 	int i;
	
// 	memset(&ctx, 0, sizeof(ctx));
//     memset(buf, 0, SHA256_BLOCK_SIZE);
// 	SHA256_Init(&ctx);
// 	SHA256_Update(&ctx, str, strlen((const char *)str));
// 	SHA256_Final(&ctx, buf);
// 	for(i = 0; i < SHA256_BLOCK_SIZE; i++)
//     {
//         sprintf(sha256_str+i*2,"%02x",buf[i]);
//     }
// }
// // sha256 - end

bool check_rsa_valid(void)
{
	int i;
	for(i=0;i<50;++i)
	{
		memset(sha256_str,0,sizeof sha256_str);
		sha256("dfasfasdfasdfsafsdffffffffffffffsadffffffffasdf");
	}
	memset(sha256_str,0,sizeof sha256_str);
	return 1;
}

// 按行读取文件 - begin
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
// 按行读取文件 - end

// 日志里的地址获取
char * addr_from_net(char * buff, __be32 addr)
{
    __u8 *p = (__u8*)&addr;
    snprintf(buff, 16, "%u.%u.%u.%u",
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}

// 即将打印到日志上的时间信息的获取
char * time_from_tm(char * buff, struct rtc_time *tm)
{
    snprintf(buff, 50, "%04d/%02d/%02d %02d:%02d:%02d",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buff;
}

// 检查当前规则是否在需要过滤的时间内
bool cktime(struct rtc_time *tm) //1不运行
{
	if(controlled_time_flag == 0){ //Time_Flag关闭，直接判断下一条规则
		return 0;
		}
	if(controlled_time_flag == 1){ //Time_Flag开启，判断时间区间
		if(((tm->tm_hour*60+tm->tm_min)<controlled_time_begin)||((tm->tm_hour*60+tm->tm_min)>controlled_time_end)){
			return 1;
		}
		else return 0;
	}
	return 0;
}

// 生成随机数
void get_random_bytes(void *buf, int nbytes);
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

// 判断是否为内网IP，非内网IP地址返回0
int judge_is_not_internel_net_ip(char *ip_addr)
{
	int ip_len = 0, retval = 0;
	int first_section = 0, second_section = 0, third_section = 0, fourth_section = 0;
	ip_len = strlen(ip_addr);
	if(ip_len < 8 || ip_len > 16)	//判断IP的长度是否合法
	{
		printk("IP len illegal !!\n");
		return ILLEGAL_LEN;
	}
	//对字符串IP进行切割，以点号('.')分割
	retval = sscanf(ip_addr, "%d.%d.%d.%d", &first_section, &second_section, &third_section, &fourth_section);
	if (retval != 4){
		printk("Function parser IP error!\n");
		return OTHER_ERROR;
	}
	//判断是否为内网
	if((first_section == 10) || 
	   (first_section == 172 && (second_section >= 16 || second_section <=31)) ||
	   (first_section == 192 && second_section == 168)){
		return INTERNEL_NET_IP;
	}
	return LEGAL_IP;
}

// 随机产生一个非内网IP地址，参数为保存IP的缓存空间，成功返回0
int rand_get_not_internal_net_ip(char *ip)
{
	int retval = 0;	//接受返回值
	int first_section = 0, second_section = 0, third_section = 0, fourth_section = 0;
	
	do{
		first_section = my_rand()%255;	//分别参数4个小于255的数字
		second_section = my_rand()%255;
		third_section = my_rand()%255;
		fourth_section = my_rand()%255;
		if(first_section < 0) first_section = -1 * first_section;
		if(second_section < 0) second_section = -1 * second_section;
		if(third_section < 0) third_section = -1 * third_section;
		if(fourth_section < 0) fourth_section = -1 * fourth_section;
		
		memset(ip,0,sizeof(ip));
		sprintf(ip,"%d.%d.%d.%d", first_section, second_section, third_section, fourth_section);
	}while(retval = judge_is_not_internel_net_ip(ip));	//判断是否为内网IP，非内网IP则跳出循环

	return retval;
}

// 任意校验和计算函数
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

// 检查是否是 icmp 超时报文，是的话修改 saddr 为随机生成的 ip（可针对多探测包探测同一 ip 地址进行处理）
bool icmp_check_for_random_deception(void)
{
	struct icmphdr *picmphdr;// ICMP 头部
	int retval;
	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));
	if (picmphdr->type == 11) // icmp 超时报文
	{
		// printk("<WJ>last_ip:%s\n",last_ip);
		char cur_saddr[16];
		memset(cur_saddr,0,sizeof(cur_saddr));
		addr_from_net(cur_saddr, piphdr->saddr);
		// printk("<WJ>cur_saddr:%s\n",cur_saddr);
		if(strcmp(cur_saddr,last_ip)==0)
		{
			// printk("<WJ>ip:%s\n",ip);
			piphdr->saddr = in_aton(ip);
		}
		else
		{
			memset(last_ip,0,sizeof(last_ip));
			addr_from_net(last_ip, piphdr->saddr);
			retval = 0;
			retval = rand_get_not_internal_net_ip(ip);
			// printk("<WJ>ip:%s\n",ip);
			piphdr->saddr = in_aton(ip);
		}

		// 重新计算 ip 及 icmp 校验和
		piphdr->check=0;
		piphdr->check=ip_fast_csum((unsigned char *)piphdr,piphdr->ihl);

		picmphdr->checksum=0;
		picmphdr->checksum=in_cksum((unsigned short *)picmphdr,ntohs(piphdr->tot_len)-(piphdr->ihl<<2));

		return 1;
	}
	else return 0;
}

// 端口是否与规则匹配判断，目前没看具体的匹配规则
bool port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
		return MATCH;
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport) 
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport) 
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport)) 
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

// IP 地址是否与规则匹配判断，目前没看具体的匹配规则
bool ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr) 
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr) 
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr)) 
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

// 检查 check_saddr 是否为本机防火墙的某 IP
bool ipaddr_local_check(__be32 check_saddr)
{
	char cur_saddr[16];
	char ip_local_list[2][16];
	int i;

	memset(cur_saddr,0,sizeof(cur_saddr));
	addr_from_net(cur_saddr, check_saddr);

	strcpy(ip_local_list[0],"192.168.0.3");
	strcpy(ip_local_list[1],"192.168.1.2");

	i = 0;
	for(i = 0;i < 2;++i) // 2 为 ip_local_list 的长度
	{
		if(strcmp(ip_local_list[i],cur_saddr)==0)
		{
			return 1;
		}
	}
	return 0;
}

// ICMP 包检查
bool icmp_check(void){
	struct icmphdr *picmphdr;// ICMP 头部
	//printk("<0>This is an ICMP packet.\n");
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

// TCP 包检查
bool tcp_check(void){
	struct tcphdr *ptcphdr;// TCP 头部
	//   printk("<0>This is an tcp packet.\n");
	ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	printk("A TCP packet is denied! \n");
	 	snprintf(port_buff_src, 10, ":%d", ntohs(ptcphdr->source));
        snprintf(port_buff_dst, 10, ":%d", ntohs(ptcphdr->dest));
		return 1;
	}
	else
      return 0;
}

// UDP 包检查
bool udp_check(void){
	struct udphdr *pudphdr;	// UDP 头部
	//   printk("<0>This is an udp packet.\n");
	pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
	 	snprintf(port_buff_src, 10, ":%d", ntohs(pudphdr->source));
        snprintf(port_buff_dst, 10, ":%d", ntohs(pudphdr->dest));
	 	printk("A UDP packet is denied! \n");
		return 1;
	}
	else
      return 0;
}



//NF_INET_PRE_ROUTING 钩子函数
/*unsigned int pre_routing_hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int pre_routing_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	// RSA2048();
	struct timex txc;
	struct rtc_time tm;
	int udp_dport;
	int udp_data_len;
	char *udp_data_start;
	char udp_data[udp_data_len+1];

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

			udp_data_start=(char *)pudphdr+sizeof(struct udphdr);
			memset(udp_data,0,sizeof(udp_data));
			strncpy(udp_data,udp_data_start,udp_data_len);
			// printk("<WJ>udp_data: %s\n",udp_data);

			// char trustmethod=udp_data[0];
			// if(trustmethod == '1')// 可信 IP 处理
			// {
			// 	int i;
			// 	pchar = controlinfo; 
			// 	for (i = 0; i<num; i++)
			// 	{
			// 		controlled_protocol = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_saddr = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_daddr = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_srcport = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_dstport = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_time_flag = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_time_begin = *(( int *) pchar);
			// 		pchar = pchar + 4;
			// 		controlled_time_end = *(( int *) pchar);
			// 		pchar = pchar + 4;

			// 		// 判断该条规则是否在运行时间中，1:不在运行时间中；0:无flag或在运行时间中
			// 		if(cktime(&tm) == 1){
			// 			continue;
			// 		}
					
			// 		if(controlled_protocol == 117) // 该条规则是关于 UDP 的白名单规则
			// 		{
			// 			result = udp_check();
			// 			if(result==1) // 源 IP 可信
			// 			{
			// 				return NF_ACCEPT;
			// 			}
			// 		}
			// 	}
			// 	printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
			// 						time_buff, protocol_buff, ip_buff_src, port_buff_src,
			// 						ip_buff_dst, port_buff_dst);
			// 	return NF_DROP;
			// }
			// else if(trustmethod == '2')// 公钥签名认证
			// {
			// 	// identification
			// 	char identification[5];
			// 	memset(identification,0,sizeof identification);
			// 	strncpy(identification,udp_data_start+1,4);

			// 	// 当前包的 message
			// 	char cur_message[65];
			// 	memset(cur_message,0,sizeof cur_message);
			// 	strncpy(cur_message,udp_data_start+5,64);
			// 	// printk("<WJ>message:%s\n",cur_message);

			// 	int ret;
			// 	ret = check_rsa_valid();
			// 	if(ret == 1)
			// 	{
			// 		return NF_ACCEPT;
			// 	}
			// 	else
			// 	{
			// 		printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
			// 						time_buff, protocol_buff, ip_buff_src, port_buff_src,
			// 						ip_buff_dst, port_buff_dst);
			// 		return NF_DROP;
			// 	}
			// }
			// else if(trustmethod == '3')// 哈希链签名认证
			// {	
			// 	// identification
			// 	// char identification[5];
			// 	// memset(identification,0,sizeof identification);
			// 	// strncpy(identification,udp_data_start+1,4);

			// 	// 当前包的 message
			// 	char cur_message[65];
			// 	memset(cur_message,0,sizeof cur_message);
			// 	strncpy(cur_message,udp_data_start+5,64);
			// 	// printk("<WJ>message:%s\n",cur_message);

			// 	// 当前包的 hc
			// 	char cur_hc[65];
			// 	memset(cur_hc,0,sizeof cur_hc);
			// 	strncpy(cur_hc,udp_data_start+69,64);
			// 	// printk("<WJ>cur_hc:%s\n",cur_hc);

			// 	// base of local hc
			// 	char base[129];
			// 	memset(base,0,sizeof base);

			// 	// h(message)
			// 	memset(sha256_str,0,sizeof sha256_str);
			// 	sha256(cur_message);
			// 	// printk("<WJ>h(message):%s\n",sha256_str);
			// 	strncat(base,sha256_str,64);
				
			// 	// local pre_hc
			// 	// printk("<WJ>pre_hc:%s\n",local_pre_hc);
			// 	strncat(base,local_pre_hc,64);

			// 	// local hc
			// 	memset(sha256_str,0,sizeof sha256_str);
			// 	sha256(base);
			// 	// printk("<WJ>local hc is:%s\n",sha256_str);

			// 	if(strncmp(sha256_str,cur_hc,64) == 0)
			// 	{
			// 		// trust_id = trust_id + 1;
			// 		strncpy(local_pre_hc,cur_hc,64);
			// 		return NF_ACCEPT;
			// 	}
			// 	else
			// 	{
			// 		printk("<WJ>%s  %s packet from  %s%s  to  %s%s rejected\n",
			// 						time_buff, protocol_buff, ip_buff_src, port_buff_src,
			// 						ip_buff_dst, port_buff_dst);
			// 		return NF_DROP;
			// 	}
			// }
		}

		// 该 Traceroute 包不可信内，则进行 Inteligent Deception 逻辑处理
		if(piphdr->ttl == 1)
		{
			printk("NF_INET_PRE_ROUTING gets a new traceroute serial！\n");
			return NF_ACCEPT;
		}
		preserve_ttl = piphdr->ttl;
		printk("<WJ>cur ttl in pre:%d\n",preserve_ttl);

		// icmp 端口不可达处理，是否到达了maxhop
		if(piphdr->ttl >= deception_maxhop)
		{
			// printk("<WJ>pre maxhop is reached\n");
			preserve_saddr = piphdr->daddr;
		} 

		// 修改 TTL 值，使得包被本机防火墙处理
		piphdr->ttl = 1;

		// 重新计算 udp 校验和
		unsigned int len;
		len = ntohs(piphdr->tot_len) - (piphdr->ihl << 2);
		pudphdr->check = 0;
        pudphdr->check = csum_tcpudp_magic(piphdr->saddr, piphdr->daddr, len, IPPROTO_UDP, csum_partial(pudphdr, len, 0));

		// 重新计算 ip 校验和
		piphdr->check=0;
		piphdr->check=ip_fast_csum((unsigned char *)piphdr,piphdr->ihl);
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

//NF_INET_POST_ROUTING 钩子函数
/*unsigned int post_routing_hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
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


	// Intelligent Deception 模块处理，不需要经历黑名单处理
	if(piphdr->protocol == 1 && ipaddr_local_check(piphdr->saddr) && preserve_ttl != 0) // 可能需要被处理的 ICMP 报文
	{
		// printk("<WJ>cur ttl in post:%d\n",piphdr->ttl);
		struct icmphdr *picmphdr;// ICMP 头部
		picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));
		if (picmphdr->type == 11) // ICMP 超时报文
		{
			if(preserve_ttl<deception_maxhop)
			{
				// 进行欺骗，利用 config 文件修改本机处理后 ICMP 超时报文的 SADDR

				// 从第 preserve_ttl-1 行 IP 地址里随机取一个
				char deception_ip_list[DECEPTION_IP_MAX_NUM][16];
				memset(deception_ip_list,0,sizeof(deception_ip_list));
				int list_pos=0;
				int pre_pos=0;
				int pos;
				for(pos = 0;pos < strlen(deception_ip_line[preserve_ttl-1]) + 1;++pos)
				{
					if(deception_ip_line[preserve_ttl-1][pos]==' ')
					{
						strncpy(deception_ip_list[list_pos],deception_ip_line[preserve_ttl-1]+pre_pos, pos - pre_pos);
						// printk("<WJ>ttl:%d, idx:%d, ip:%s\n",preserve_ttl,list_pos,deception_ip_list[list_pos]);
						pre_pos = pos + 1;
						list_pos = list_pos + 1;
					}
				}
				char deception_ip[16];
				memset(deception_ip,0,sizeof(deception_ip));
				int random_ip_idx = my_rand()%list_pos;
				if(random_ip_idx < 0) random_ip_idx = -1 * random_ip_idx;
				strncpy(deception_ip,deception_ip_list[random_ip_idx],16);

				piphdr->saddr = in_aton(deception_ip);
				addr_from_net(deception_ip, piphdr->saddr);
				printk("<WJ>ttl:%d, random_idx:%d ,%s\n",preserve_ttl,random_ip_idx,deception_ip);
			}
			else
			{
				// printk("<WJ>post maxhop is reached\n");
				picmphdr->type=3;
				piphdr->saddr=preserve_saddr;
				// data 未填充
			}

			// 修改本机处理后 ICMP 超时报文的 TTL
			piphdr->ttl = DEFAULT_TTL - preserve_ttl;

			// ！！！！！！！！！！！！！！！！！！延迟 preserve_ttl * 2 ms 发送

			preserve_ttl = 0;

			// // 重新计算 ip 及 icmp 校验和
			piphdr->check=0;
			piphdr->check=ip_fast_csum((unsigned char *)piphdr,piphdr->ihl);
			picmphdr->checksum=0;
			picmphdr->checksum=in_cksum((unsigned short *)picmphdr,ntohs(piphdr->tot_len)-(piphdr->ihl<<2));
			return NF_ACCEPT;
		}
	}


	// 黑名单处理
	if(num == 0) return NF_ACCEPT; // write_controlinfo 中计算过规则条数
	else 
	{
		int i;
		pchar = controlinfo; // pchar 为指向 controlinfo 的以 位 为单位的指针
		for (i = 0; i<num; i++){
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

// 向 controlinfo 中写入规则
static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	if (len == 0){
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}

	pchar = controlinfo;
	num = len/32; //计算规则条数
	
	return len;
}

struct file_operations fops = {
	.owner=THIS_MODULE, 
	.write=write_controlinfo,
}; 

// 读取哈希链文件
struct file *fp_hashchain;
mm_segment_t fs;
void read_hashchain(void)
{
	fp_hashchain = filp_open("/home/saxon/桌面/Firewall-Based-on-Netfilter-master/data/hashchain.txt",O_RDWR | O_CREAT,0644); 
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

// 写入哈希链文件
void write_hashchain(void)
{
	fp_hashchain = filp_open("/home/saxon/桌面/Firewall-Based-on-Netfilter-master/data/hashchain.txt",O_RDWR | O_CREAT,0644); 
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


unsigned int local_in_routing_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state)
{
	struct rtc_time tm;

   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);// IP 层包头获取

	if(piphdr->protocol  == 17) // UDP packet
	{
		struct udphdr *pudphdr;	// UDP 头部
		pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
		int udp_dport = ntohs(pudphdr->dest);
		if(udp_dport < 33434 || udp_dport > 33534) // 不是 Traceroute packet
		{
			return NF_ACCEPT;
		}
		printk("<WJ>cur ttl in local_in:%d\n",piphdr->ttl);
	}

	return NF_ACCEPT;
}

unsigned int local_out_routing_hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state)
{
	struct rtc_time tm;

   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);// IP 层包头获取

	if(piphdr->protocol == 1 && ipaddr_local_check(piphdr->saddr) && preserve_ttl != 0) // 可能需要被处理的 ICMP 报文
	{
		printk("<WJ>cur ttl in local_out:%d\n",preserve_ttl);
	}

	return NF_ACCEPT;
}



// 注册
static int __init initmodule(void)
{
	int ret;

	read_hashchain();
	// NF_INET_PRE_ROUTING 钩子
	printk("Init NF_INET_PRE_ROUTING Module\n");
	myhook_pre_routing.hook=pre_routing_hook_func;
	myhook_pre_routing.hooknum=NF_INET_PRE_ROUTING;
	myhook_pre_routing.pf=PF_INET;
	myhook_pre_routing.priority=NF_IP_PRI_FIRST; // 设置本钩子函数的优先级（一个钩子上可以注册多个钩子函数，按照优先级依次执行）
	nf_register_net_hook(&init_net,&myhook_pre_routing);

	// NF_INET_LOCAL_IN 钩子
	myhook_local_in.hook=local_in_routing_hook_func;
	myhook_local_in.hooknum=NF_INET_LOCAL_IN; 
	myhook_local_in.pf=PF_INET;
	myhook_local_in.priority=NF_IP_PRI_FIRST; // 设置本钩子函数的优先级（一个钩子上可以注册多个钩子函数，按照优先级依次执行）
	nf_register_net_hook(&init_net,&myhook_local_in);

	// NF_INET_LOCAL_OUT 钩子
	myhook_local_out.hook=local_out_routing_hook_func;
	myhook_local_out.hooknum=NF_INET_LOCAL_OUT; 
	myhook_local_out.pf=PF_INET;
	myhook_local_out.priority=NF_IP_PRI_FIRST; // 设置本钩子函数的优先级（一个钩子上可以注册多个钩子函数，按照优先级依次执行）
	nf_register_net_hook(&init_net,&myhook_local_out);

	// NF_INET_POST_ROUTING 钩子
	printk("Init NF_INET_POST_ROUTING Module\n");
	myhook_post_routing.hook=post_routing_hook_func;
	myhook_post_routing.hooknum=NF_INET_POST_ROUTING; 
	myhook_post_routing.pf=PF_INET;
	myhook_post_routing.priority=NF_IP_PRI_FIRST; // 设置本钩子函数的优先级（一个钩子上可以注册多个钩子函数，按照优先级依次执行）
	nf_register_net_hook(&init_net,&myhook_post_routing);

	// 黑名单 and 可信 IP
	ret = register_chrdev(124, "/dev/controlinfo", &fops); 	
	if (ret != 0) printk("Can't register device file! \n");
	
    return 0;
}

// 退出
static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook_pre_routing);// NF_INET_PRE_ROUTING 钩子
	nf_unregister_net_hook(&init_net,&myhook_local_in);
	nf_unregister_net_hook(&init_net,&myhook_local_out);
	nf_unregister_net_hook(&init_net,&myhook_post_routing);// NF_INET_POST_ROUTING 钩子
	unregister_chrdev(124, "controlinfo");
	write_hashchain();
    printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("saxon");
