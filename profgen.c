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
	u64		TSOffset;		// current timestamp offset 

	u16		MACProto;			
	u8		IPProto;			
	u8		IPDSCP;			
	u8		VLAN;			
	u8		MPLS;			

	u32		PktCnt;			// number of packets
	u32		PktPos;			// current output pos

	u16*	PktLen;		// list of packet sizes
	u32*	PktDTS;			// time deltas between packets

	u8*		Packet;			// packet data to 9K jumbo frames

} FlowRecord_t;

static u32					s_FlowListCnt	= 0;				// current list of flows
static u32					s_FlowListMax	= 10e6;				// max number of flows 
static FlowRecord_t* 		s_FlowList		= NULL;				// list of active flows 

static u64					s_MemoryByte	= 0;


//-------------------------------------------------------------------------------------------------

float 			randu			(float mean, float scale);
unsigned long 	FCSCalculate	(unsigned char* c, int Len);

//-------------------------------------------------------------------------------------------------

static int PacketGenerate(FlowRecord_t *F)
{

	// allocate packet buffer
	F->Packet = malloc(16*1024);
	assert(F->Packet != NULL);

	memset(F->Packet, 0x00, 16*1024);

	// generate packet
	fEther_t* Ether = (fEther_t*)F->Packet;

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

	u32 i			= randu(0, 0x100000000); 

	IPv4->Src.IP[0] = (i >> 24) & 0xFF;
	IPv4->Src.IP[1] = (i >> 16) & 0xFF;
	IPv4->Src.IP[2] = (i >>  8) & 0xFF;
	IPv4->Src.IP[3] = (i >>  0) & 0xFF;

	IPv4->Dst.IP[0] = (i >> 24) & 0xFF;
	IPv4->Dst.IP[1] = (i >> 16) & 0xFF;
	IPv4->Dst.IP[2] = (i >>  8) & 0xFF;
	IPv4->Dst.IP[3] = 240;

	IPv4->CSum 		= 0;

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
		//F->PayloadLength = (u8*)(TCP + 1) - (u8*)Ether;
		//F->TCP			= TCP;
	}
	else if (F->IPProto == IPv4_PROTO_UDP)
	{
		UDPHeader_t* UDP = (UDPHeader_t*)(IPv4 + 1);

		UDP->PortSrc	= randu(0, 0x10000);
		UDP->PortDst	= randu(0, 0x10000);
		UDP->Length		= 0;
		UDP->CSUM		= 0;

		// total length of the header
		//F->PayloadLength = (u8*)(UDP + 1) - (u8*)Ether;
		//F->UDP			= UDP;
	}
	else
	{
		fprintf(stderr, "IPProto: %d not supported!\n", F->IPProto);
		return -1;
	}
}

//-------------------------------------------------------------------------------------------------
// patch up any length fields 
static int PacketUpdate(FlowRecord_t *F, u32 Length)
{
	// generate packet
	fEther_t* Ether 	= (fEther_t*)F->Packet;

	Ether->Proto 		= swap16(ETHER_PROTO_IPV4);

	IP4Header_t* IPv4 	= (IP4Header_t*)(Ether + 1);
	IPv4->Len 			= swap16(Length - sizeof(fEther_t));
	IPv4->CSum 			= 0;

	if (F->IPProto == IPv4_PROTO_TCP)
	{
		TCPHeader_t* TCP = (TCPHeader_t*)(IPv4 + 1);
	}
	else if (F->IPProto == IPv4_PROTO_UDP)
	{
		UDPHeader_t* UDP = (UDPHeader_t*)(IPv4 + 1);

		UDP->Length		= swap16( Length - ((u8*)UDP - F->Packet));
	}

	// caluclate FCS
	u32* pFCS 	= (u32*)(F->Packet + Length - 4);
	pFCS[0] 	= FCSCalculate(F->Packet, Length -4); 

}

//-------------------------------------------------------------------------------------------------

int Profile_Generate(const char *Histogram, u32 Amplify)
{
	// allocate flow list
	s_FlowListCnt 	= 0;
	s_FlowList 		= malloc( s_FlowListMax * sizeof(FlowRecord_t) );
	s_MemoryByte	+= s_FlowListMax * sizeof(FlowRecord_t);

	// parse the profile
	FILE *Input = fopen(Histogram, "r");
	if (Input == NULL)
	{
		fprintf(stderr, "Failed to open %s file\n", Histogram);
		return -1;
	}

	// read in the flow list
	u64 TotalPkt = 0;
	bool IsExit = false;
	while (Input != NULL)
	{
		HistogramDump_t Flow;

		int rlen = fread(&Flow, 1, sizeof(Flow), Input);
		if (rlen != sizeof(Flow)) break;

		switch (Flow.signature)
		{
		case HISTOGRAM_SIG_V1:
		{
			PacketInfo_t* PktInfo = malloc( sizeof(PacketInfo_t) * Flow.TotalPkt );
			for (int i=0; i < Flow.TotalPkt; i++)
			{
				fread(&PktInfo[i], 1, sizeof(PacketInfo_t), Input);
			}

			// amplifiy amount 
			for (int a=0; a < Amplify; a++)
			{

				// create enry
				FlowRecord_t* F = &s_FlowList[s_FlowListCnt++];	
				memset(F, 0, sizeof(FlowRecord_t));

				F->TSOffset		= 0;

				// for subsuiquent copie add a random offset up to 1mse
				F->TSOffset		= randu(0, 1e6);

				F->MACProto		= Flow.MACProto;
				F->IPProto		= Flow.IPProto;
				F->IPDSCP		= Flow.IPDSCP;
				F->VLAN			= Flow.VLAN;
				F->MPLS			= Flow.MPLS;

				// generate the packet
				PacketGenerate(F);

				F->PktPos		= 0; 
				F->PktCnt		= Flow.TotalPkt;
				F->PktLen		= malloc(sizeof(u16) * F->PktCnt); 
				F->PktDTS		= malloc(sizeof(u32) * F->PktCnt); 

				s_MemoryByte	+= F->PktCnt * (sizeof(u16) + sizeof(u32)); 

				u64 Duration = 0;
				u64 Byte = 0;
				for (int i=0; i < Flow.TotalPkt; i++)
				{
					F->PktLen[i] 	= PktInfo[i].PktSize;
					F->PktDTS[i] 	= PktInfo[i].TSDiff;

					Duration 		+= PktInfo[i].TSDiff;
					Byte			+= PktInfo[i].PktSize;
				}

				TotalPkt += Flow.TotalPkt;

				float Bps = (Byte * 8.0) / (Duration / 1e9);
				fprintf(stderr, "Flow: %8i : PktCnt: %8i Duration:%16.6f sec %10.3f KB Bps:%12.3f Mbps\n", Flow.FlowID, Flow.TotalPkt, Duration/1e9, Byte / 1024.0, Bps/1e6); 
			}
		}
		break;

		default:
			fprintf(stderr, "Invalid Signature: %08x\n", Flow.signature);
			IsExit = true;
			break;
		}
		if (IsExit) break;
	}
	fprintf(stderr, "Total Memory Usage: %.3f MB\n", s_MemoryByte / 1e9);

	// write output pcap header
	PCAPHeader_t		Header;
	Header.Magic		= PCAPHEADER_MAGIC_NANO;
	Header.Major		= PCAPHEADER_MAJOR;
	Header.Minor		= PCAPHEADER_MINOR;
	Header.TimeZone		= 0;
	Header.SigFlag		= 0;
	Header.SnapLen		= 65535;
	Header.Link			= PCAPHEADER_LINK_ETHERNET;
	if (fwrite(&Header, sizeof(Header), 1, stdout) != 1)
	{
		fprintf(stderr, "Failed to write header to output\n");
		return 0;
	}

	// outpput one flow block
	u64 PktCnt = 0;
	while (true)
	{
		u64 BestTS				= -1; 
		FlowRecord_t* BestFlow = NULL;
		for (int i=0; i < s_FlowListCnt; i++)
		{
			FlowRecord_t* F = &s_FlowList[i];

			// no packets left 
			if (F->PktPos >= F->PktCnt) continue;

			u64 TS = F->TSOffset + F->PktDTS[F->PktPos];
			if (TS < BestTS)
			{
				BestTS 		= TS;
				BestFlow 	= F;
			}
		}

		if (BestFlow == NULL)
		{
			printf("all flows done\n");
			break;
		}

		// length for this instance
		u32 PktLength = BestFlow->PktLen[BestFlow->PktPos];
		assert(PktLength < 9*1024);

		// path any length fields
		PacketUpdate(BestFlow, PktLength);

		// pcap header
		PCAPPacket_t Pkt;
		Pkt.Sec 			= BestTS / 1e9; 
		Pkt.NSec 			= BestTS - (u64)Pkt.Sec * 1000000000ULL; 

		Pkt.LengthWire		= PktLength;
		Pkt.LengthCapture	= PktLength;
		fwrite(&Pkt, 1, sizeof(Pkt), stdout);

		// output packet

		fwrite(BestFlow->Packet, 1, PktLength, stdout);

		// update flow offset
		BestFlow->TSOffset += BestFlow->PktDTS[BestFlow->PktPos];

		// next pkt in flow
		BestFlow->PktPos++;

		PktCnt++;
	}


/*
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

	if (Histogram_Stats)
	{
		fprintf(stdout, "-------------------- Format --------------------\n");
		fprintf(stdout, "Flow <N> | ETHProto | IPProto | IPDSCP | VLAN bits | MPLS bits | First TS | Total Packets\n");
		fprintf(stdout, "\tTSDiff PktSize | TSDiff PktSize | ... |\n");
		fprintf(stdout, "----------------------- --- --------------------\n\n");

		while ((Buffer - fb) < st.st_size)
		{
			HistogramDump_t *H = (HistogramDump_t *)Buffer;
			if (H->signature != HISTOGRAM_SIG_V1)
			{
				fprintf(stderr, "Histogram signature invalid!\n");
				break;
			}
			fprintf(stdout, "Flow %u | %s | %s | %s | %d,%d,%d | %d,%d,%d | %llu | %llu",
					H->FlowID, MACProto2Str(H->MACProto), IPProto2Str(H->IPProto), IPDSCP2Str(H->IPDSCP),
					GET_VLAN_BIT(H, 0), GET_VLAN_BIT(H, 1), GET_VLAN_BIT(H, 2),
					GET_MPLS_BIT(H, 0), GET_MPLS_BIT(H, 1), GET_MPLS_BIT(H, 2),
					H->FirstTS, H->TotalPkt);

			PacketInfo_t *P = (PacketInfo_t *)(H+1);
			for (u32 i = 0; i < H->TotalPkt ; i++)
			{
				if (i%10 == 0) fprintf(stdout, "\n\t");
				fprintf(stdout, "%u %d | ", P->TSDiff, P->PktSize);
				P = P+1;
			}
			fprintf(stdout, "\n");
			Buffer = Buffer + sizeof(HistogramDump_t) + H->TotalPkt * sizeof(PacketInfo_t);
		}
		fclose(F);
		free(fb);
		free(OutputBuffer);
		return 0;
	}

	// write output pcap header
	PCAPHeader_t		Header;
	Header.Magic		= PCAPHEADER_MAGIC_NANO;
	Header.Major		= PCAPHEADER_MAJOR;
	Header.Minor		= PCAPHEADER_MINOR;
	Header.TimeZone		= 0;
	Header.SigFlag		= 0;
	Header.SnapLen		= 65535;
	Header.Link			= PCAPHEADER_LINK_ETHERNET;
	if (fwrite(&Header, sizeof(Header), 1, stdout) != 1)
	{
		fprintf(stderr, "Failed to write header to output\n");
		return 0;
	}

	u64 Count = 0, SkipCount = 0;

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
		int GenFlowRet = GenerateFlow(F, H);

		u64 TS			= H->FirstTS;
		PacketInfo_t *P = (PacketInfo_t *)(H+1);

		for (u32 i = 0; i < H->TotalPkt ; i++)
		{
			// If the protocol is not supported then just skip the packet generation for this flow
			if (GenFlowRet != 0)
			{
				P = P+1;
				SkipCount++;
				continue;
			}
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
			TS					= TS + P->TSDiff;
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

			Count++;
			P = P+1;
		}
		//Buffer = (u8 *)P;
		Buffer = Buffer + sizeof(HistogramDump_t) + H->TotalPkt * sizeof(PacketInfo_t);
	}
	fclose(F);
	fprintf(stderr, "Total packet count: %llu SkipCount: %llu\n", Count, SkipCount);
	free(fb);
	free(OutputBuffer);
*/
}

