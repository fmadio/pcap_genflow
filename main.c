/* vim: set ts=4 sts=4 */
//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// PCAP flow test generation utility 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"
#include "histogram.h"

//-------------------------------------------------------------------------------------------------
typedef struct
{
	u32				IPProto;				// TCP/UDP 
	u32				PayloadLength;			// length of header bytes
	u8				Payload[128];			// first part of payload header

	IP4Header_t* 	IPv4;					// ptr to IPv4 header in the payload
	TCPHeader_t* 	TCP;					// ptr to TCP header in the payload
	UDPHeader_t* 	UDP;					// ptr to UDP header in the payload

} Flow_t;

static u32		s_FlowCnt 	= 0;			// number of active flows
static Flow_t*	s_FlowList	= NULL;			// flow headers

//-------------------------------------------------------------------------------------------------

double TSC2Nano = 0;

static u64 s_TargetPktCnt			= 1e6;			// number of packets to generate
static u64 s_TargetFlowCnt			= 1e3;			// number of flows to generate 
static u64 s_TargetPktSize			= 512;			// packet size to generate 
static u64 s_TargetPktSlice			= 9200;			// how much to slice each packet 
static u64 s_TargetBps				= 100e9;		// output data rate
static bool s_IsIMIX				= false;		// generate packets based on imix distribution
static bool Histogram_Stats			= false;		// generate histogram text format stats only
static char *s_Histogram			= NULL;			// Historam file
static u32 s_ProfileAmplify			= 1;			// how much to amplify the profile data
static u64 s_TargetByte				= 0;			// target total byte count

//-------------------------------------------------------------------------------------------------

int Profile_Generate(const char *Histogram, u32 Amplify, u64 TargetTotalBytes);

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	fprintf(stderr, "pcap_genflow \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-v                 : verbose output\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "--pktcnt   <total packts>        : total number of packets to output\n");
	fprintf(stderr, "--flowcnt  <total flows>         : total number of flows\n");
	fprintf(stderr, "--pktsize  <packet size>         : size of each packet\n");
	fprintf(stderr, "--pktslice <packet slice amount> : packet slicing amount (default 0)\n");
	fprintf(stderr, "--bps      <bits output rate>    : output generation rate (e.g. 1e9 = 1Gbps)\n");
	fprintf(stderr, "--imix                           : user standard IMIX packet size distribution\n");
	fprintf(stderr, "--histogram <filename>           : histogram (binary format) file name to generate packet flow\n");
	fprintf(stderr, "--histogram-bin2txt <filename>   : converts histogram binary file to text format\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
}

//-------------------------------------------------------------------------------------------------
// FCS generator
/*
#define CRCPOLY2 0xEDB88320UL  // left-right reversal 
static unsigned long FCSCalculate(int n, unsigned char c[])
{
	int i, j;
	unsigned long r;

	r = 0xFFFFFFFFUL;
	for (i = 0; i < n; i++) {
		r ^= c[i];
		for (j = 0; j < CHAR_BIT; j++)
			if (r & 1) r = (r >> 1) ^ CRCPOLY2;
			else       r >>= 1;
	}
	return r ^ 0xFFFFFFFFUL;
}
*/
/* generated using the AUTODIN II polynomial
 *	x^32 + x^26 + x^23 + x^22 + x^16 +
 *	x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
 */
static const u32 crctab[256] = 
{
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

#define CRC(crc, ch)	 (crc = (crc >> 8) ^ crctab[(crc ^ (ch)) & 0xff])
unsigned long FCSCalculate(unsigned char* c, int Len)
{
	u32 crc 		= 0xffffffff;
	u32 crc32_total	= 0;
    crc32_total 	= ~crc32_total ;
	for (int i=0; i < Len; i++)
	{
		u32 b = c[i]; 
		crc = (crc >> 8) ^ crctab[(crc ^ (b)) & 0xff];
/*
u32 crc_swap = 0;
for (int j=0; j < 32; j++)
{
	crc_swap |= (((crc^0xffffffff) >> j) & 1) << (31 - j);
}
printf("%4i : %08x\n", i, crc ^ 0xffffffff, crc_swap);
*/

	}
	return crc ^ 0xffffffff;
}


//-------------------------------------------------------------------------------------------------

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
static inline uint16_t IP4Checksum(u16 *addr, int len)
{
  s32 count = len;
  u32 sum = 0;
  u16 answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  do
  {
    sum += addr[0];

   	addr += 1; 
    count -= 2;
  } while (count > 1);

  // Add left-over byte, if any.
  u8* addr8 = (u8*)addr;
  if (count > 0) {
    sum += addr8[0];
	addr8++;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}
/*
static u16 TCPSum16(IPv4Header_t* IPHeader, void* _D, u32 Len)
{
    u8* D   = (u8 *)_D;
    u32 Sum = 0;
    u8* E   = D + (Len&(~1));

    while (D < E)
    {
        u16 v = (D[1]<<8) | (D[0]);
        Sum += v;
        D += 2;
    }

    if (Len&1)
    {
        Sum += *D;
    }

    u16* Src = (u16*)&IPHeader->Src;
    u16* Dst = (u16*)&IPHeader->Dst;

    Sum += Src[0];
    Sum += Src[1];

    Sum += Dst[0];
    Sum += Dst[1];

    Sum += swap16(IPHeader->Proto);
    Sum += swap16(Len);

    while (Sum>>16)
	{
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
	}

    return ~Sum;
}
*/


//-------------------------------------------------------------------------------------------------
// gaussian random number, mean=0, stdev=1
// per Knuth method 3 http://c-faq.com/lib/gaussian.html
double randg(double mean, double stdev)
{
	static double V1, V2, S;
	static int phase = 0;
	double X;

	if (phase == 0) 
	{
		do 
		{
			double U1 = (double)rand() / RAND_MAX;
			double U2 = (double)rand() / RAND_MAX;

			V1 = 2 * U1 - 1;
			V2 = 2 * U2 - 1;
			S = V1 * V1 + V2 * V2;

		} while(S >= 1 || S == 0);

		X = V1 * sqrt(-2 * log(S) / S);
	} 
	else
	{
		X = V2 * sqrt(-2 * log(S) / S);
	}
	phase = 1 - phase;

	// shape it so has a default stdev of 4
	return mean + stdev * X * (1.0 / 4);
}



/*
#define PI 3.141592654
double randg(double mean, double stdev)
{
	static double U, V;
	static int phase = 0;
	double Z;

	if(phase == 0) {
		U = (rand() + 1.) / (RAND_MAX + 2.);
		V = rand() / (RAND_MAX + 1.);
		Z = sqrt(-2 * log(U)) * sin(2 * PI * V);
	} else
		Z = sqrt(-2 * log(U)) * cos(2 * PI * V);

	phase = 1 - phase;

	return Z;

}
*/

//-------------------------------------------------------------------------------------------------
// generate uniform random number
/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

	To the extent possible under law, the author has dedicated all copyright
	and related and neighboring rights to this software to the public domain
	worldwide. This software is distributed without any warranty.

	See <http://creativecommons.org/publicdomain/zero/1.0/>. */


/*	This is xoshiro256** 1.0, our all-purpose, rock-solid generator. It has
	excellent (sub-ns) speed, a state (256 bits) that is large enough for
	any parallel application, and it passes all tests we are aware of.

	For generating just floating-point numbers, xoshiro256+ is even faster.

	The state must be seeded so that it is not everywhere zero. If you have
	a 64-bit seed, we suggest to seed a splitmix64 generator and use its
	output to fill s. */

static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}


static uint64_t s[4] = { 756065179, 776531419, 797003437, 817504253 } ;

float randu(float mean, float scale) 
{
	const uint64_t result_starstar = rotl(s[1] * 5, 7) * 9;

	const uint64_t t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;

	s[3] = rotl(s[3], 45);

	// build a floating point number 1.0 + rand parts
	u32 f = 0x3F800000 | (result_starstar >> 32) & 0x7fffff;
	float f1 = *((float*)&f);

	// noramlize from [1.0, 2.0] -> [0.0, 1.0]
	return mean + scale*(f1 - 1.0);
}

//-------------------------------------------------------------------------------------------------

void trace(char* Message, ...)
{
	va_list arglist;
	va_start(arglist, Message);

	char buf[16*1024];
	vsprintf(buf, Message, arglist);

	fprintf(stderr, "%s", buf);
	fflush(stderr);
}

//-------------------------------------------------------------------------------------------------

static int GenerateFlow(Flow_t *F, HistogramDump_t *H)
{
	F->IPProto = H->IPProto;

	// generate packet
	fEther_t* Ether = (fEther_t*)&F->Payload;

	Ether->Src[0] 	= randu(0, 0x100);
	Ether->Src[1] 	= randu(0, 0x100);
	Ether->Src[2] 	= randu(0, 0x100);
	Ether->Src[3] 	= randu(0, 0x100);
	Ether->Src[4] 	= randu(0, 0x100);
	Ether->Src[5] 	= randu(0, 0x100);

	Ether->Dst[0] 	= randu(0, 0x100);
	Ether->Dst[1] 	= randu(0, 0x100);
	Ether->Dst[2] 	= randu(0, 0x100);
	Ether->Dst[3] 	= randu(0, 0x100);
	Ether->Dst[4] 	= randu(0, 0x100);
	Ether->Dst[5] 	= randu(0, 0x100);

	/* TODO: IPv6 ? */
	// IPv4
	Ether->Proto 	= swap16(ETHER_PROTO_IPV4);

	IP4Header_t* IPv4 = (IP4Header_t*)(Ether + 1);
	IPv4->Version 	= 0x45;
	IPv4->Service 	= 0;
	IPv4->Len 		= 0;
	IPv4->Ident 	= 0;
	IPv4->Frag 		= (2<<5);
	IPv4->TTL 		= 64;
	IPv4->Proto 	= F->IPProto;

	u32 i			= H->FlowID;

	IPv4->Src.IP[0] = (i >> 24) & 0xFF;
	IPv4->Src.IP[1] = (i >> 16) & 0xFF;
	IPv4->Src.IP[2] = (i >>  8) & 0xFF;
	IPv4->Src.IP[3] = (i >>  0) & 0xFF;

	IPv4->Dst.IP[0] = (i >> 24) & 0xFF;
	IPv4->Dst.IP[1] = (i >> 16) & 0xFF;
	IPv4->Dst.IP[2] = (i >>  8) & 0xFF;
	IPv4->Dst.IP[3] = 240;

	IPv4->CSum 		= 0;

	F->IPv4			= IPv4;

	if (F->IPProto == IPv4_PROTO_TCP)
	{
		TCPHeader_t* TCP = (TCPHeader_t*)(IPv4 + 1);
		TCP->PortSrc	= randu(0, 0x10000);
		TCP->PortDst	= randu(0, 0x10000);
		TCP->SeqNo		= 0;
		TCP->AckNo		= 0;
		TCP->Flags		= swap16((sizeof(TCPHeader_t) >> 2) << 12);
		TCP->Window		= 0;
		TCP->Urgent		= 0;
		TCP->CSUM		= 0;

		// total length of the header
		F->PayloadLength = (u8*)(TCP + 1) - (u8*)Ether;
		F->TCP			= TCP;
	}
	else if (F->IPProto == IPv4_PROTO_UDP)
	{
		UDPHeader_t* UDP = (UDPHeader_t*)(IPv4 + 1);

		UDP->PortSrc	= randu(0, 0x10000);
		UDP->PortDst	= randu(0, 0x10000);
		UDP->Length		= 0;
		UDP->CSUM		= 0;

		// total length of the header
		F->PayloadLength = (u8*)(UDP + 1) - (u8*)Ether;
		F->UDP			= UDP;
	}
	else
	{
		fprintf(stderr, "IPProto: %d not supported!\n", F->IPProto);
		return -1;
	}
	return 0;
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	bool IsChunked 	= false; 
	s32 CPUID 		= -1;

	fprintf(stderr, "PCAP Flow Packet Generator : FMADIO 10G 40G 100G Packet Capture : http://www.fmad.io\n");
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		else if (strcmp(argv[i], "--pktcnt") == 0)
		{
			s_TargetPktCnt = atof(argv[i+1]);
			fprintf(stderr, "  PktCnt: %lli\n", s_TargetPktCnt);
			i++;	
		}
		else if (strcmp(argv[i], "--flowcnt") == 0)
		{
			s_TargetFlowCnt = atof(argv[i+1]);
			fprintf(stderr, "  FlowCnt: %lli\n", s_TargetFlowCnt);
			i++;	
		}
		else if (strcmp(argv[i], "--pktsize") == 0)
		{
			s_TargetPktSize = atof(argv[i+1]);
			fprintf(stderr, "  PacketSize: %lli\n", s_TargetPktSize);
			i++;	
		}
		else if (strcmp(argv[i], "--pktslice") == 0)
		{
			s_TargetPktSlice = atof(argv[i+1]);
			fprintf(stderr, "  PacketSlice: %lli\n", s_TargetPktSlice);
			i++;	
		}
		else if (strcmp(argv[i], "--bps") == 0)
		{
			s_TargetBps = atof(argv[i+1]);
			fprintf(stderr, "  Target Rate: %.3f Gbps\n", s_TargetBps / 1e9);
			i++;
		}
		else if (strcmp(argv[i], "--chunked") == 0)
		{
			fprintf(stderr, "  Chunked Packet Output\n"); 
			IsChunked = true;
		}
		else if (strcmp(argv[i], "--cpu") == 0)
		{
			CPUID = atoi(argv[i+1]);	
			fprintf(stderr, "  CPU Assignment %i\n", CPUID); 
		}
		else if (strcmp(argv[i], "--imix") == 0)
		{
			s_IsIMIX = true;
			fprintf(stderr, "  IMIX Packet Distributioni\n"); 
		}
		else if (strcmp(argv[i], "--profile") == 0)
		{
			s_Histogram 	= argv[i+1];
			fprintf(stderr, "  Histogram filename: %s\n", s_Histogram);
			i++;
		}
		else if (strcmp(argv[i], "--amplify") == 0)
		{
			s_ProfileAmplify = atoi(argv[i+1]);
			fprintf(stderr, "  Amplify Profile: %i\n", s_ProfileAmplify);
			i++;
		}
		else if (strcmp(argv[i], "--byte") == 0)
		{
			s_TargetByte 	= (u64) atof(argv[i+1]);
			fprintf(stderr, "  Target: %.3f GB\n", s_TargetByte/1e9);
			i++;
		}
		else
		{
			fprintf(stderr, "invalid optin (%s)\n", argv[i]);
			assert(false);	
		}

	}
	if (CPUID >= 0) 
	{
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (CPUID, &Thread0CPU);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &Thread0CPU);
	}

	if (s_Histogram)
	{
		Profile_Generate(s_Histogram, s_ProfileAmplify, s_TargetByte);
		return 0;
	}

	FILE* OutFile = stdout;

	// write output pcap header 
	PCAPHeader_t		Header;
	Header.Magic		= IsChunked ? PCAPHEADER_MAGIC_FMAD : PCAPHEADER_MAGIC_NANO;
	Header.Major		= PCAPHEADER_MAJOR;
	Header.Minor		= PCAPHEADER_MINOR;
	Header.TimeZone		= 0; 
	Header.SigFlag		= 0; 
	Header.SnapLen		= 65535; 
	Header.Link			= PCAPHEADER_LINK_ETHERNET; 
	if (fwrite(&Header, sizeof(Header), 1, OutFile) != 1)
	{
		fprintf(stderr, "Failed to write header to output\n");
		return 0;
	}

	// start time
	u64 TSStart 		= clock_ns();

	u64 TargetPkt		= s_TargetPktCnt;
	u32 MTU				= 1500;
	u32 TargetFlow		= s_TargetFlowCnt;
	u32 LengthSlice		= s_TargetPktSlice;				// slice amount
	float TargetGbps 	= s_TargetBps;

	// output payload buffer
	u8* OutputBuffer	= malloc(16*1024);
	memset(OutputBuffer, 0, 16*1024);

	// generate flows
	s_FlowCnt		= s_TargetFlowCnt;
	s_FlowList		= (Flow_t*)malloc( s_FlowCnt * sizeof(Flow_t) );
	memset(s_FlowList, 0, s_FlowCnt * sizeof(Flow_t) );
	for (int i=0; i < s_FlowCnt; i++)
	{
		if ((i % (u32)10e3) == 0) fprintf(stderr, "gen flow: %i\n", i);

		Flow_t* F = &s_FlowList[i];	

		F->IPProto = IPv4_PROTO_TCP;

		// generate packet	
		fEther_t* Ether = (fEther_t*)&F->Payload;	

		Ether->Src[0] 	= randu(0, 0x100);
		Ether->Src[1] 	= randu(0, 0x100);
		Ether->Src[2] 	= randu(0, 0x100);
		Ether->Src[3] 	= randu(0, 0x100);
		Ether->Src[4] 	= randu(0, 0x100);
		Ether->Src[5] 	= randu(0, 0x100);

		Ether->Dst[0] 	= randu(0, 0x100);
		Ether->Dst[1] 	= randu(0, 0x100);
		Ether->Dst[2] 	= randu(0, 0x100);
		Ether->Dst[3] 	= randu(0, 0x100);
		Ether->Dst[4] 	= randu(0, 0x100);
		Ether->Dst[5] 	= randu(0, 0x100);

		// IPv4
		Ether->Proto 	= swap16(ETHER_PROTO_IPV4);

		IP4Header_t* IPv4 = (IP4Header_t*)(Ether + 1);	
		IPv4->Version 	= 0x45;
		IPv4->Service 	= 0;
		IPv4->Len 		= swap16( s_TargetPktSize - sizeof(fEther_t) - sizeof(IP4Header_t) );
		IPv4->Ident 	= 0;
		IPv4->Frag 		= (2<<5);
		IPv4->TTL 		= 64;
		IPv4->Proto 	= F->IPProto;
/*
		IPv4->Src.IP[0] = randu(0, 0x100);
		IPv4->Src.IP[1] = randu(0, 0x100);
		IPv4->Src.IP[2] = randu(0, 0x100);
		IPv4->Src.IP[3] = randu(0, 0x100);

		IPv4->Dst.IP[0] = randu(0, 0x100);
		IPv4->Dst.IP[1] = randu(0, 0x100);
		IPv4->Dst.IP[2] = randu(0, 0x100);
		IPv4->Dst.IP[3] = randu(0, 0x100);
*/

		IPv4->Src.IP[0] = (i >> 24) & 0xFF; 
		IPv4->Src.IP[1] = (i >> 16) & 0xFF; 
		IPv4->Src.IP[2] = (i >>  8) & 0xFF; 
		IPv4->Src.IP[3] = (i >>  0) & 0xFF; 

		IPv4->Dst.IP[0] = (i >> 24) & 0xFF; 
		IPv4->Dst.IP[1] = (i >> 16) & 0xFF; 
		IPv4->Dst.IP[2] = (i >>  8) & 0xFF; 
		IPv4->Dst.IP[3] = 240; 

		IPv4->CSum 		= 0; 
		IPv4->CSum 		= IP4Checksum( (u16*)IPv4, sizeof(IP4Header_t) );

		TCPHeader_t* TCP = (TCPHeader_t*)(IPv4 + 1);
		TCP->PortSrc	= randu(0, 0x10000);
		TCP->PortDst	= randu(0, 0x10000);
		TCP->SeqNo		= 0; 
		TCP->AckNo		= 0; 
		TCP->Flags		= swap16((sizeof(TCPHeader_t) >> 2) << 12);
		TCP->Window		= 0; 
		TCP->Urgent		= 0; 
		TCP->CSUM		= 0; 

		// total length of the header
		F->PayloadLength = (u8*)(TCP + 1) - (u8*)Ether;
	}

	u64 PktCnt 			= 0;
	double TSOffset 	= 0;
	double NSperBit		= 1e9 / TargetGbps;

	u32 ChunkBufferPos 	= 0;
	u32 ChunkBufferMax 	= kKB(256);
	u8* ChunkBuffer 	= malloc( 1024*1024); 

	FMADHeader_t		ChunkHeader;
	memset(&ChunkHeader, 0, sizeof(ChunkHeader));

	int wlen;
	while (PktCnt < TargetPkt)
	{
		//u32 Length = 64 + (MTU - 64) * fabs(randg(0, 1)); 
		u32 Length = s_TargetPktSize; 


		// IMIX packet size distribution 
		if (s_IsIMIX)
		{
			static u32 IMIXCnt = 0;
			switch (IMIXCnt)
			{
			case  0: Length =  576; break;
			case  1: Length =   64; break;
			case  2: Length =  576; break;
			case  3: Length =   64; break;
			case  4: Length =  576; break;
			case  5: Length =   64; break;
			case  6: Length =  576; break;
			case  7: Length =   64; break;
			case  8: Length =   64; break;
			case  9: Length =   64; break;
			case 10: Length =   64; break;
			case 11: Length = 1500; break;
			default:
				fprintf(stderr, "invalid %i\n", IMIXCnt);
				assert(false);
			}
			IMIXCnt = (IMIXCnt + 1) % 12;
		}

		// TSOffset is sub-nano, need to seperate into a base + offset
		u64 TS = TSStart + TSOffset;

		PCAPPacket_t Pkt;
		Pkt.Sec = TS / 1e9; 
		Pkt.NSec = TS - (u64)Pkt.Sec * 1000000000ULL; 

		Pkt.LengthWire		= Length;
		Pkt.LengthCapture	= (Length < LengthSlice) ? Length : LengthSlice;

		u32 FlowIndex 		= PktCnt % (u32)s_FlowCnt; 
		assert(FlowIndex < s_FlowCnt);
		Flow_t* F = &s_FlowList[FlowIndex];	

		// select a randomized flow
		//u32 FlowIndex 	= randu(0, s_FlowCnt);
		//u32 FlowIndex 	= ((u64)rand() * (u64)s_FlowCnt) / (u64)RAND_MAX;
		//FlowIndex 		= max32(FlowIndex, s_FlowCnt - 1);	
		if (!IsChunked)
		{
			// write header
			wlen = fwrite(&Pkt, 1, sizeof(Pkt), OutFile);
			if (wlen != sizeof(Pkt)) break;

			// write header
			wlen = fwrite(F->Payload, 1, F->PayloadLength, OutFile);
			if (wlen != F->PayloadLength) break;

			// write padding
			wlen = fwrite(OutputBuffer, 1, Pkt.LengthCapture - F->PayloadLength, OutFile);
			if (wlen != Pkt.LengthCapture - F->PayloadLength) break;
		}
		else
		{
			FMADPacket_t* P 	= (FMADPacket_t*)(ChunkBuffer + ChunkBufferPos);
			P->TS 				= TS;
			P->LengthWire		= Pkt.LengthWire;
			P->LengthCapture 	= Pkt.LengthCapture;
			P->PortNo			= 0;
			P->Flag				= 0;
			P->pad0				= 0;

			memcpy(P+1, F->Payload, F->PayloadLength); 

			ChunkBufferPos += sizeof(PCAPPacket_t) + Pkt.LengthCapture;	

			ChunkHeader.PktCnt		+= 1;
			ChunkHeader.ByteWire	+= Pkt.LengthWire;
			ChunkHeader.ByteCapture	+= Pkt.LengthCapture;

			if (ChunkHeader.TSStart == 0) ChunkHeader.TSStart = TS; 
			ChunkHeader.TSEnd 		= TS; 

			// flush buffer
			if (ChunkBufferPos > ChunkBufferMax - kKB(16))
			{
				// write chunk header
				ChunkHeader.Length = ChunkBufferPos;	
				fwrite(&ChunkHeader, 1, sizeof(ChunkHeader), OutFile);

				fwrite(ChunkBuffer, 1, ChunkBufferPos, OutFile);
				ChunkBufferPos = 0;

				// reset
				memset(&ChunkHeader, 0, sizeof(ChunkHeader));
			}
		}

		//fprintf(stderr, "%8i\n", Length);
		PktCnt		+= 1;
		TSOffset 	+= Length * 8 * NSperBit;
	}
	return 0;
}
