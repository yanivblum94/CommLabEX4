#ifndef L3_H_
#define L3_H_

#include "L2.h"
#include "L4.h"

class L3{
public:

	/*
		L3 constructor, use it to initiate variables and data structure that you wish to use.
		Should remain empty by default (if no global class variables are beeing used).
	*/
	L3();

	/*
		sendToL3 is called by the upper layer via the upper layer's L3 pointer.
		sendData is the pointer to the data L4 wish to send.
		sendDataLen is the length of that data.
		srcIP is the machines IP address that L4 supplied.
		destIP is the destination IP address that L4 supplied.
		debug is to enable print (use true)
	*/
	int sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP, bool debug = false);

	/*
		recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
		recvData is the pointer to the data L4 wish to receive.
		recvDataLen is the length of that data.
		debug is to enable print (use true)
	*/
	int recvFromL3(byte *recvData, size_t recvDataLen, bool debug = false);


	/*
		Implemented for you
	*/
	void setLowerInterface(L2* lowerInterface);
	/*
		Implemented for you
	*/
	void setUpperInterface(L4* upperInterface);

	/*
		Implemented for you
	*/
	std::string getLowestInterface();

private:
	L2* lowerInterface;
	L4* upperInterface;
};





#endif /* L3_H_ */