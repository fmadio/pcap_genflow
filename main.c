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

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	fprintf(stderr, "pcap_genflow \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-v                 : verbose output\n");
	fprintf(stderr, "-vv                : dump every packet\n");
	fprintf(stderr, "\n");
}

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

int main(int argc, char* argv[])
{
	fprintf(stderr, "PCAP Flow Packet Generator : FMADIO 10G 40G 100G Packet Capture : http://www.fmad.io\n");
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
	}

	FILE* OutFile = stdout;

	// write output pcap header 
	PCAPHeader_t		Header;
	Header.Magic		= PCAPHEADER_MAGIC_NANO;
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

u32 Histo[9200];
memset(Histo, 0, sizeof(Histo));

	// start time
	u64 TSStart 		= clock_ns();

	u64 TargetPkt		= 4e6;
	u32 MTU				= 1500;
	u32 TargetFlow		= 100e3;
	u32 LengthSlice		= 192;				// slice amount
	float TargetGbps 	= 1e9;
	//float TargetGbps 	= 0.1e9;

	// output payload buffer
	u8* OutputBuffer	= malloc(16*1024);
	memset(OutputBuffer, 0, 16*1024);

	// generate flows
	s_FlowCnt		= TargetFlow;
	s_FlowList		= (Flow_t*)malloc( s_FlowCnt * sizeof(Flow_t) );
	memset(s_FlowList, 0, s_FlowCnt * sizeof(Flow_t) );
	for (int i=0; i < s_FlowCnt; i++)
	{
		if ((i % (u32)10e3) == 0) fprintf(stderr, "gen flow: %i\n", i);

		Flow_t* F = &s_FlowList[i];	

		F->IPProto = IPv4_PROTO_TCP;

		// generate packet	
		fEther_t* Ether = (fEther_t*)&F->Payload;	

		Ether->Src[0] = randu(0, 0x100);
		Ether->Src[1] = randu(0, 0x100);
		Ether->Src[2] = randu(0, 0x100);
		Ether->Src[3] = randu(0, 0x100);
		Ether->Src[4] = randu(0, 0x100);
		Ether->Src[5] = randu(0, 0x100);

		Ether->Dst[0] = randu(0, 0x100);
		Ether->Dst[1] = randu(0, 0x100);
		Ether->Dst[2] = randu(0, 0x100);
		Ether->Dst[3] = randu(0, 0x100);
		Ether->Dst[4] = randu(0, 0x100);
		Ether->Dst[5] = randu(0, 0x100);

		// IPv4
		Ether->Proto = swap16(ETHER_PROTO_IPV4);

		IP4Header_t* IPv4 = (IP4Header_t*)(Ether + 1);	
		IPv4->Version 	= 45;
		IPv4->Service 	= 0;
		IPv4->Len 		= 0;
		IPv4->Ident 	= 0;
		IPv4->Frag 		= 0;
		IPv4->TTL 		= 64;
		IPv4->Proto 	= F->IPProto;
		IPv4->CSum 		= 0;
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
		//IPv4->Src.IP4 	= i;

		IPv4->Src.IP[0] = (i >> 24) & 0xFF; 
		IPv4->Src.IP[1] = (i >> 16) & 0xFF; 
		IPv4->Src.IP[2] = (i >>  8) & 0xFF; 
		IPv4->Src.IP[3] = (i >>  0) & 0xFF; 
		IPv4->Dst.IP4 	= 0xffffffff - i;

		TCPHeader_t* TCP = (TCPHeader_t*)(IPv4 + 1);
		TCP->PortSrc	= randu(0, 0x10000);
		TCP->PortDst	= randu(0, 0x10000);
		TCP->SeqNo		= 0; 
		TCP->AckNo		= 0; 
		TCP->Flags		= 0; 
		TCP->Window		= 0; 
		TCP->Urgent		= 0; 
		TCP->CSUM		= 0; 

		// total length of the header
		F->PayloadLength = (u8*)(TCP + 1) - (u8*)Ether;
	}

	u64 PktCnt 		= 0;
	double TSOffset = 0;
	double NSperBit	= 1e9 / TargetGbps;

	int wlen;
	while (PktCnt < TargetPkt)
	{
		//u32 Length = 64 + (MTU - 64) * fabs(randg(0, 1)); 
		u32 Length = 512; 

		// TSOffset is sub-nano, need to seperate into a base + offset
		u64 TS = TSStart + TSOffset;

		PCAPPacket_t Pkt;
		Pkt.Sec = TS / 1e9; 
		Pkt.NSec = TS - (u64)Pkt.Sec * 1000000000ULL; 

		Pkt.LengthWire		= Length;
		Pkt.LengthCapture	= (Length < LengthSlice) ? Length : LengthSlice;

		// write header
		wlen = fwrite(&Pkt, 1, sizeof(Pkt), OutFile);
		if (wlen != sizeof(Pkt)) break;

		// select a randomized flow
		//u32 FlowIndex 	= randu(0, s_FlowCnt);
		//u32 FlowIndex 	= ((u64)rand() * (u64)s_FlowCnt) / (u64)RAND_MAX;
		//FlowIndex 		= max32(FlowIndex, s_FlowCnt - 1);	
		u32 FlowIndex 		= PktCnt % (u32)s_FlowCnt; 
		/*	
		static u32 FlowIndex = 0;
		FlowIndex++;
		if (FlowIndex >= s_FlowCnt) FlowIndex = 0;
		*/
		Flow_t* F = &s_FlowList[FlowIndex];	

		// write header
		wlen = fwrite(F->Payload, 1, F->PayloadLength, OutFile);
		if (wlen != F->PayloadLength) break;

		// write padding
		wlen = fwrite(OutputBuffer, 1, Pkt.LengthCapture - F->PayloadLength, OutFile);
		if (wlen != Pkt.LengthCapture - F->PayloadLength) break;

		//fprintf(stderr, "%8i\n", Length);

		PktCnt++;

		TSOffset += Length * 8 * NSperBit;

		Histo[Length/32]++;
	}

/*
u32 max = 0;
for (int i=0; i < 9200/32; i++)
{
	max = max32(Histo[i], max);
}
for (int i=0; i < 9200/32; i++)
{
	fprintf(stderr, "%5i : %8i :", i*32, Histo[i]);
	for (int j=0; j < Histo[i] * 100 / max; j++) fprintf(stderr, "*");
	fprintf(stderr, "\n");
}
*/

	return 0;
}
