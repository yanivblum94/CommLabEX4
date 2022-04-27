#ifndef L2_H_
#define L2_H_

#include "Types.h"
#include <string>

class L3;

class L2 {
public:

	L2();

	/*
		Writes the data on the wire.
		debug - if set to true, prints data for debuging
		retry - number of times to retry if send fails. default value is 3
		timeout - default time in seconds to wait for a send to fail. default value is 2
	*/
	int sendToL2(byte *sendData, size_t sendDataLen, bool debug = false, int retry = 3, double timeout = 2.0);

	/*
		Fills the recvData buf with the data received from L3.
		debug - if set to true, prints data for debuging
	*/
	int recvFromL2(byte *recvData, size_t recvDataLen, bool debug = false);

	void setUpperInterface(L3* upperInterface);
	std::string getLowestInterface();

private:
	std::string iface;
	L3 * upperInterface;
	void * recvPacket;

	std::string getInter();
};

#endif /* L2_H_ */