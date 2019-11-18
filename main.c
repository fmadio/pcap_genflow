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
static char *s_Histogram			= NULL;			// Historam file

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
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
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

static int CreateHistogramFlow(const char *Histogram)
{
	FILE *F = fopen(Histogram, "r");
	if (F == NULL)
	{
		fprintf(stderr, "Failed to open %s file\n", Histogram);
		return -1;
	}

	struct stat st;
	memset(&st, 0, sizeof(st));
	if (stat(Histogram, &st) != 0)
	{
		fprintf(stderr, "stat %s failed\n", Histogram);
		fclose(F);
		return -1;
	}
	fprintf(stderr, "Histogram file size: %lu Bytes\n", st.st_size);

	u8 *fb = malloc(st.st_size +  1);
	if (fb == NULL)
	{
		fprintf(stderr, "failed to malloc file size memory\n");
		fclose(F);
		return -1;
	}
	int ret = fread(fb, st.st_size, 1, F);
	if (ret != 1)
	{
		fprintf(stderr, "fread failed!\n");
		fclose(F);
		return -1;
	}

	u8* OutputBuffer    = malloc(16*1024);
	memset(OutputBuffer, 0, 16*1024);

	Flow_t Flow;
	u8 *Buffer = fb;
	u64 count = 0;

	while ((Buffer - fb) < st.st_size)
	{
		Flow_t *F = &Flow;
		HistogramDump_t *H = (HistogramDump_t *)Buffer;
		if (H->signature != HISTOGRAM_SIG_V1)
		{
			fprintf(stderr, "Histogram signature invalid!\n");
			break;
		}
		//fprintf(stderr, "Histogram: %u %d %d %d %llu %llu\n", H->FlowID, H->MACProto, H->IPProto, H->DSCPStr, H->FirstTS, H->TotalPkt);

		memset(F, 0, sizeof(F));
		GenerateFlow(F, H);

		PacketInfo_t *P = (PacketInfo_t *)(H+1);

		for (u32 i = 0; i < H->TotalPkt ; i++)
		{
			//F->IPv4->Len		= swap16(P->PktSize - sizeof(fEther_t) - sizeof(IP4Header_t));
			F->IPv4->Len		= swap16(P->PktSize - sizeof(fEther_t));
			F->IPv4->CSum		= 0;
			F->IPv4->CSum		= IP4Checksum( (u16*)F->IPv4, sizeof(IP4Header_t));

			if (H->IPProto == IPv4_PROTO_UDP)
			{
				F->UDP->Length	= swap16(P->PktSize - F->PayloadLength - sizeof(UDPHeader_t));
			}
			//fprintf(stderr, "P->PktSize: %u F->PayloadLength: %d UDPHeader_t: %d UDP len: %X\n", P->PktSize, F->PayloadLength, sizeof(UDPHeader_t), F->UDP->Length);

			// PCAP prepare logic
			PCAPPacket_t Pkt;
			u64 TS				= H->FirstTS + P->TSDiff;
			Pkt.Sec				= TS / 1e9;
			Pkt.NSec			= (u64)Pkt.Sec * 1000000000ULL;

			Pkt.LengthWire		= P->PktSize;
			//Pkt.LengthCapture	= P->PktSize;
			Pkt.LengthCapture	= (P->PktSize < s_TargetPktSlice) ? P->PktSize : s_TargetPktSlice;

			int wlen;
			// write header
			wlen = fwrite(&Pkt, sizeof(Pkt), 1, stdout);
			if (wlen != 1) break;
			wlen = fwrite(F->Payload, F->PayloadLength, 1, stdout);
			if (wlen != 1) break;

			// write padding
			wlen = fwrite(OutputBuffer, Pkt.LengthCapture - F->PayloadLength, 1, stdout);
			if (wlen != 1) break;

			count++;
			P = P+1;
		}
		//Buffer = (u8 *)P;
		Buffer = Buffer + sizeof(HistogramDump_t) + H->TotalPkt * sizeof(PacketInfo_t);
	}
	fclose(F);
	fprintf(stderr, "Total packet count: %llu\n", count);
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
		else if (strcmp(argv[i], "--histogram") == 0)
		{
			s_Histogram = argv[i+1];
			fprintf(stderr, "  Histogram: %s\n", s_Histogram);
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

	if (s_Histogram)
	{
		CreateHistogramFlow(s_Histogram);
		return 0;
	}

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
