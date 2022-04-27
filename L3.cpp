//Yaniv Blum 312253586
//Gai Greenberg 205431224

#include "L3.h"
#include <iostream>
#include <winsock2.h>

using namespace std;

#define DebugPrint(str) if(debug) cout << str 
#define PRINT_COMMA DebugPrint(" , ")

//Masks
#define CHECK_SUM_MASK 0xFFFF
#define CHECK_SUM_SIZE_MASK 0x80000000
#define CHECK_SUM_SHIFT_RIGHT 16
#define IHL_MASK 0xF

//offsets
#define TYPE_OF_SERVICE_OFFSET 1
#define TOTAL_LENGTH_OFFSET 2
#define IDENTIFICATIONS_OFFSET 4
#define FLAGS_OFFSET 6
#define TTL_OFFSET 8
#define PROTOCOL_OFFSET 9
#define HEADER_CHECK__SUM_OFFSET 10
#define SRC_ADDRESS_OFFSET 12
#define DST_ADDRESS_OFFSET 16

//constants
#define IP_VERSION 4 //ipv4
#define IP_NO_FRAG_FLAG 2//2 bytes
#define TTL 64// 64 bytes
#define ICMP_PROTOCOL 1//1 byte
#define IP_TOS 0
#define IP_HEADER_SIZE 20 //20 bytes
#define ETHERNET_HEADER_SIZE 14// 14 bytes
#define IP_MAX_FRAME_SIZE 1500//MTU


class IP_packet {
public:
	struct header_IP {
		uint8_t version : 4;
		uint8_t ihl : 4;
		uint8_t type_of_service;
		uint16_t total_length;
		uint16_t identifications;
		uint8_t flags : 3;
		uint16_t fragmentation_offset : 13;
		uint8_t time_to_live;
		uint8_t protocol;
		uint16_t header_checksum;
		uint32_t source_address;
		uint32_t destination_address;
	};
	struct header_IP header;
	size_t len_of_data_layer4;
	byte * data_from_layer4;

	IP_packet::IP_packet(bool debug);
	IP_packet(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug);
	~IP_packet();
	void get_header_ip(byte* buff);
	bool check_packet();
	void print_packet();
	void print_IP(byte* adr);
	uint16_t get_checksum();
	int unpack_packet(byte* binary_data, int data_size);
	bool sanity_check(byte* binary_data, int data_size);

private:
	bool debug;
};


IP_packet::IP_packet(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug)
{
	//data
	this->data_from_layer4 = sendData;
	this->len_of_data_layer4 = sendDataLen;
	this->header.total_length = (uint16_t)(IP_HEADER_SIZE + this->len_of_data_layer4);

	//IP's
	this->header.source_address = inet_addr(srcIP.c_str());
	this->header.destination_address = inet_addr(destIP.c_str());
	// debug
	this->debug = debug;

	//constants
	this->header.version = IP_VERSION;
	this->header.ihl = IP_HEADER_SIZE / sizeof(word);
	this->header.type_of_service = IP_TOS;
	this->header.flags = IP_NO_FRAG_FLAG;
	this->header.time_to_live = TTL;
	this->header.protocol = ICMP_PROTOCOL;
	this->header.fragmentation_offset = 0;
	this->header.identifications = 0;

	//calculated CRC
	this->header.header_checksum = get_checksum();
}

IP_packet::IP_packet(bool debug)
{
	this->debug = debug;
}

IP_packet::~IP_packet() {}

void IP_packet::get_header_ip(byte* buff)
{
	header_IP hdr = this->header;
	*buff = (hdr.version << 4) + hdr.ihl; //1st byte
	*(buff + TYPE_OF_SERVICE_OFFSET) = hdr.type_of_service;
	*((uint16_t*)(buff + TOTAL_LENGTH_OFFSET)) = htons(hdr.total_length);
	*((uint16_t*)(buff + IDENTIFICATIONS_OFFSET)) = htons(hdr.identifications);
	uint16_t flags_byte = hdr.flags;
	flags_byte = flags_byte << 13; //13 bits offset
	flags_byte += hdr.fragmentation_offset;
	*((uint16_t*)(buff + FLAGS_OFFSET)) = htons(flags_byte);
	*(buff + TTL_OFFSET) = hdr.time_to_live;
	*(buff + PROTOCOL_OFFSET) = hdr.protocol;
	*((uint16_t*)(buff + HEADER_CHECK__SUM_OFFSET)) = htons(hdr.header_checksum);
	*((uint32_t*)(buff + SRC_ADDRESS_OFFSET)) = hdr.source_address;
	*((uint32_t*)(buff + DST_ADDRESS_OFFSET)) = hdr.destination_address;
}


uint16_t IP_packet::get_checksum()
{
	uint32_t check_sum = 0;
	//get binary header 
	byte* dump = new byte[IP_HEADER_SIZE];
	get_header_ip(dump);
	const byte* hdr = dump;
	int header_len = IP_HEADER_SIZE;
	do {
		check_sum += *((uint16_t*)hdr);
		if (check_sum & CHECK_SUM_SIZE_MASK) {
			check_sum = (check_sum >> CHECK_SUM_SHIFT_RIGHT) + (check_sum & CHECK_SUM_MASK);
		}
		header_len -= 2;
		hdr += 2;
	} while (header_len > 1);

	if (header_len != 0) 
		check_sum += *hdr;
	
	while (check_sum >> CHECK_SUM_SHIFT_RIGHT) {
		check_sum = (check_sum >> CHECK_SUM_SHIFT_RIGHT) + (check_sum & CHECK_SUM_MASK);
	}

	delete[] dump;
	return htons(~check_sum);
}


bool IP_packet::check_packet()
{
	bool res = true;

	//check if it's icmp
	if (this->header.protocol != ICMP_PROTOCOL) {
		DebugPrint("ERROR! protocol is not ICMP\n");
		res = false;
	}

	// CRC check (should be 0)
	if (this->get_checksum() != 0) {
		DebugPrint("ERROR! Incorrect header_checksum\n");
		res = false;
	}


	//check if the length of data is longest then max length allowed
	if (this->len_of_data_layer4 > (IP_MAX_FRAME_SIZE - IP_HEADER_SIZE)) {
		DebugPrint("ERROR! Data Length Too big\n");
		res = false;
	}

	//if time_to_live is 0
	if (this->header.time_to_live == 0) {
		DebugPrint("ERROR! Time To Live Is Zero\n");
		res = false;
	}

	return res;
}

bool IP_packet::sanity_check(byte* binary_data, int data_size) {

	this->header.version = *binary_data >> 4;
	if (this->header.version != IP_VERSION) {
		DebugPrint("[ERROR!] packet version is not supported (not IP_VERSION)\n");
		return false;
	}

	this->header.ihl = *binary_data & IHL_MASK;

	if (this->header.ihl != IP_HEADER_SIZE / sizeof(word)) {
		DebugPrint("[ERROR!] incorrect ihl\n");
		return false;
	}

	if (data_size < IP_HEADER_SIZE) {
		DebugPrint("ERROR! packet size is smaller than IP_HEADER_SIZE\n");
		return false;
	}

	return true;
}

int IP_packet::unpack_packet(byte* binary_data, int data_size) {
	if (!sanity_check(binary_data, data_size)) {
		DebugPrint("[ERROR!] packet is invalid\n");
		return 0;
	}

	this->header.type_of_service = *(binary_data + TYPE_OF_SERVICE_OFFSET);
	this->header.total_length = ntohs(*((uint16_t*)(binary_data + TOTAL_LENGTH_OFFSET)));
	this->header.identifications = ntohs(*((uint16_t*)(binary_data + IDENTIFICATIONS_OFFSET)));
	uint16_t flags_byte = ntohs(*((uint16_t*)(binary_data + FLAGS_OFFSET)));
	this->header.flags = flags_byte >> 13;
	this->header.fragmentation_offset = flags_byte & 0x1FFFF;
	this->header.time_to_live = *(binary_data + TTL_OFFSET);
	this->header.protocol = *(binary_data + PROTOCOL_OFFSET);
	this->header.header_checksum = ntohs(*((uint16_t*)(binary_data + HEADER_CHECK__SUM_OFFSET)));
	this->header.source_address = *((uint32_t*)(binary_data + SRC_ADDRESS_OFFSET));
	this->header.destination_address = *((uint32_t*)(binary_data + DST_ADDRESS_OFFSET));
	this->len_of_data_layer4 = data_size - IP_HEADER_SIZE;
	this->data_from_layer4 = binary_data + IP_HEADER_SIZE;
	return 1;
}

void IP_packet::print_IP(byte* adr){
	for (int i = 0; i < 4; i++)
	{
		DebugPrint((uint16_t)adr[i]);
		if (i < 3)
			DebugPrint(".");
	}
}

void IP_packet::print_packet() {
	header_IP hdr = this->header;
	DebugPrint("< IP(" << std::dec << (((uint16_t)hdr.ihl) * sizeof(word)) << " bytes) :: ");
	DebugPrint("version = " << (uint16_t)hdr.version << " , ");
	DebugPrint("Header length = " << (uint16_t)hdr.ihl << " , ");
	DebugPrint("DiffServicesCP = " << (hdr.type_of_service >> 2) << " , ");
	DebugPrint("ExpCongestionNot = " << (hdr.type_of_service & 0x3) << " , ");
	DebugPrint("Total length = " << hdr.total_length << " , ");
	DebugPrint("Identifications = 0x");
	DebugPrint(std::hex << hdr.identifications << std::dec);
	PRINT_COMMA;
	DebugPrint("Flags = " << (uint16_t)hdr.flags << " , ");
	DebugPrint("Fragment Offset = " << hdr.fragmentation_offset << " , ");
	DebugPrint("TTL = " << (uint16_t)hdr.time_to_live << " , ");
	DebugPrint("Protocol= 0x");
	DebugPrint(std::hex << (uint16_t)hdr.protocol << std::dec);
	PRINT_COMMA;
	DebugPrint("Check Sum = 0x");
	DebugPrint(std::hex << hdr.header_checksum << std::dec);
	PRINT_COMMA;
	byte* src = (byte*)&(hdr.source_address);
	byte* dst = (byte*)&(hdr.destination_address);
	DebugPrint("Source IP = ");
	print_IP(src);
	PRINT_COMMA;
	DebugPrint("Destination IP = ");
	print_IP(dst);
	DebugPrint(" , >\n");
}

/*	
	L3 constructor, use it to initiate variables and data structure that you wish to use. 
	Should remain empty by default (if no global class variables are beeing used).
*/
L3::L3(){ }

/*	
	sendToL3 is called by the upper layer via the upper layer's L3 pointer.
	sendData is the pointer to the data L4 wish to send.
	sendDataLen is the length of that data.
	srcIP is the machines IP address that L4 supplied.
	destIP is the destination IP address that L4 supplied.
	debug is to enable print (use true)
*/
int L3::sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug) {
	IP_packet* packet = new IP_packet(sendData, sendDataLen, srcIP, destIP, debug); //new packet
	if ((!packet->check_packet())) { //if packet is invalid
		delete packet;
		return 0;
	}

	byte* buff = new byte[IP_MAX_FRAME_SIZE];
	packet->get_header_ip(buff); //get header ip
	//concatenate L4 data
	memcpy(buff + IP_HEADER_SIZE, packet->data_from_layer4, packet->len_of_data_layer4);
	int result = lowerInterface->sendToL2(buff, (uint16_t)(IP_HEADER_SIZE + packet->len_of_data_layer4), debug);
	delete packet;
	delete[] buff;
	return result;
}

/*
	recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
	recvData is the pointer to the data L4 wish to receive.
	recvDataLen is the length of that data.
	debug is to enable print (use true)
*/
int L3::recvFromL3(byte *recvData, size_t recvDataLen, bool debug) {
	byte *packet_buff = new byte[IP_MAX_FRAME_SIZE + ETHERNET_HEADER_SIZE];
	int data_size;
	data_size = lowerInterface->recvFromL2(packet_buff, IP_MAX_FRAME_SIZE + ETHERNET_HEADER_SIZE, debug);
	byte * frame = packet_buff + ETHERNET_HEADER_SIZE;
	IP_packet* packet = new IP_packet(debug); //empty packet
	if (!(packet->unpack_packet(frame, data_size - ETHERNET_HEADER_SIZE)) || !(packet->check_packet())) {
		delete packet;
		delete[] packet_buff;
		return 0;
	}

	DebugPrint("IP packet received\n");
	packet->print_packet();
	memcpy(recvData, packet->data_from_layer4, packet->len_of_data_layer4); //copy packet l4
	int result = packet->len_of_data_layer4;
	delete packet;
	delete[] packet_buff;
	return result;
}

/*
	Implemented for you
*/
void L3::setLowerInterface(L2* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
	Implemented for you
*/
void L3::setUpperInterface(L4* upperInterface){ this->upperInterface = upperInterface; }

/*
	Implemented for you
*/
std::string L3::getLowestInterface(){ return lowerInterface->getLowestInterface(); }