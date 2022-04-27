#include <L3.h> 

#include <WinSock2.h>
#include <iostream>


/* Collapse namespaces */
using namespace std;

void main(int argc, char *argv[]) {

	L2 * Datalink = new L2();
	L3 * Network = new L3();
	L4 * Transport = new L4();

	Datalink->setUpperInterface(Network);
	Network->setUpperInterface(Transport);
	Network->setLowerInterface(Datalink);
	Transport->setLowerInterface(Network);

	char * test = { "NetlabPingPongTest!\n" };
	size_t testLen = string(test).length();

	/* Default remote server, can be changed using command arguments */
	string dstIP = "www.google.com";
	if (argc == 2)
		dstIP = string(argv[1]);

	/* L4 tries to resolves destination IP address, if it can't it passes NULL string to L3.*/
	Transport->sendToL4((byte *)test, testLen, dstIP, "", true);
	byte * recv = new byte[512];
	Transport->recvFromL4(recv, 512, true);
	cout << "Press any key and then ENTER to quit" << endl;
	string mystr;
	cin >> mystr;
	delete[] recv;

}











