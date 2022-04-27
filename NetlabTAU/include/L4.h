#ifndef L4_H_
#define L4_H_
#include "Types.h"
#include <string>

class L3;

class L4{
public:
	L4();

	/* 
		Builds the icmp data to be passed to L3.
		destIP - given a string, L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.
		srcIP - default value is NULL. Can be set to other value of the format XXX.XXX.XXX.XXX, passed to L3
		debug - if set to true, prints data for debuging
	*/
	int sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP = "", bool debug = false);

	/*
		Fills the recvData buf with the data received from L3.
		debug - if set to true, prints data for debuging
	*/
	int recvFromL4(byte *recvData, size_t recvDataLen, bool debug = false);

	void setLowerInterface(L3* lowerInterface);
	std::string getLowestInterface();

private:
	L3* lowerInterface;
	std::string resolveIPaddr(std::string IPaddr);
};

#endif /* L4_H_ */