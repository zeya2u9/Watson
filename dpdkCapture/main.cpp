#include <vector>
#include <unistd.h>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <stdio.h>
#include "SystemUtils.h"
#include "DpdkDeviceList.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include <time.h>
#include <signal.h>
#include <errno.h>

#define MBUF_POOL_SIZE 16*1024-1
#define DEVICE_ID_1 0
#define DEVICE_ID_2 1

#define ARR_SIZE 512

unsigned long long count = 0, bits = 0;
short enable = 0, firstpkt = 0;
timespec current_time,final_time;
timespec temp_time1, temp_time2;

struct data{
      int seq;
      char buff[1500];
      int rawDataLen;
      timespec timestamp;
      pcpp::LinkLayerType layerType;
};

struct arguments{
	int fd;
	iovec *iov;
};

// Keep running flag
static bool keepRunning = true;
static bool start = false;

//global vars
//int sock1,ns1,len1;
//int sock2,ns2,len2;
//int sock3,ns3,len3;
//int sock4,ns4,len4;
static data *msg_ptr;
static unsigned int counter = 0;
//char socket_name[] = "/dev/shm/sshBruteForce\0";
//struct sockaddr_in addr1, addr2, addr3, addr4;
int f1,f2,f3,f4;

void *send(void *arg){
    while(1){
    arguments *args = (arguments *)arg;
    int write = vmsplice(args->fd,args->iov,1,0);
    if(write < 0){
        std::cerr<<"Cant vmsplice with errno"<<errno<<std::endl;
    }
    }
}

void onApplicationInterrupted(int sig)
{
        keepRunning = false;
        clock_gettime(CLOCK_REALTIME,&final_time);
        std::cout << std::endl << "Shutting down... with a count of " << count << "and a speed of " << (bits/(final_time.tv_sec-current_time.tv_sec))/(1024*1024) << "Mbits/sec" << std::endl;
    	//std::cout<<"just after receiving "<<temp_time1.tv_sec<<"."<<temp_time1.tv_nsec<<std::endl<<"just after sending to socket "<<temp_time2.tv_sec<<"."<<temp_time2.tv_nsec<<std::endl;
	close(f1);
        close(f2);
        close(f3);
        close(f4);
}

//void handler(int sig){
//    start = true;
//}

class L2FwdWorkerThread : public pcpp::DpdkWorkerThread
{
    private:
    pcpp::DpdkDevice* m_RxDevice;
    pcpp::DpdkDevice* m_TxDevice;
    bool m_Stop;
    uint32_t m_CoreId;

    public:
    // c'tor
    L2FwdWorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice);

    // d'tor (does nothing)
    ~L2FwdWorkerThread() { }

    // implement abstract method

    // start running the worker thread
    bool run(uint32_t coreId);

    // ask the worker thread to stop
    void stop();

    // get worker thread core ID
    uint32_t getCoreId() const;
};

int main(int argc, char* argv[])
{
    // Register the on app close event handler
    //pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, NULL);
    signal(SIGINT,onApplicationInterrupted);
    //signal(SIGTERM,handler);
    // Initialize DPDK
    pcpp::CoreMask coreMaskToUse = pcpp::getCoreMaskForAllMachineCores();
    pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, MBUF_POOL_SIZE);

    // Find DPDK devices
    pcpp::DpdkDevice* device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_1);
    if (device1 == NULL)
    {
    	std::cerr << "Cannot find device1 with port '" << DEVICE_ID_1 << "'" << std::endl;
    	return 1;
    }

    pcpp::DpdkDevice* device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DEVICE_ID_2);
    if (device2 == NULL)
    {
    	std::cerr << "Cannot find device2 with port '" << DEVICE_ID_2 << "'" << std::endl;
    	return 1;
    }

    // Open DPDK devices
    if (!device1->openMultiQueues(1, 1))
    {
    	std::cerr << "Couldn't open device1 #" << device1->getDeviceId() << ", PMD '" << device1->getPMDName() << "'" << std::endl;
    	return 1;
    }

    if (!device2->openMultiQueues(1, 1))
    {
    	std::cerr << "Couldn't open device2 #" << device2->getDeviceId() << ", PMD '" << device2->getPMDName() << "'" << std::endl;
    	return 1;
    }

    // Create worker threads
    std::vector<pcpp::DpdkWorkerThread*> workers;
    workers.push_back(new L2FwdWorkerThread(device1, device2));
    workers.push_back(new L2FwdWorkerThread(device2, device1));

    // Create core mask - use core 1 and 2 for the two threads
    int workersCoreMask = 0;
    for (int i = 1; i <= 2; i++)
    {
    	workersCoreMask = workersCoreMask | (1 << i);
    }

    /*if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        std::cerr<<"Socket creation error with errno: "<<errno<<std::endl;
        return -1;
    }
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_name);
    len = sizeof(addr);

    ns = connect(sock, (struct sockaddr *) &addr, len);
    if(ns == -1){
        std::cerr<<"Socket connection error with errno: "<<errno<<std::endl;
        close(sock);
        exit(1);
    }*/
/*
    //socket 1
    if ( (sock1 = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        std::cerr<<"socket error"<<std::endl;
        exit(-1);
    }

    addr1.sin_family = AF_INET;
    addr1.sin_port = htons(1234);
    if (inet_pton(AF_INET, "127.0.0.1", &addr1.sin_addr) <= 0) {
        std::cerr<<"Invalid address/ Address not supported"<<std::endl;
        return -1;
    }

    // connection of socket 1
    ns1 = connect(sock1, (struct sockaddr *) &addr1, sizeof(struct sockaddr_in));
    if (ns1 < 0) {
        std::cerr<<"cant connect to 127.0.0.1 with errno:"<<errno<<std::endl;
    }

    //socket 2
    if ( (sock2 = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        std::cerr<<"socket error"<<std::endl;
        exit(-1);
    }

    addr2.sin_family = AF_INET;
    addr2.sin_port = htons(2345);
    if (inet_pton(AF_INET, "127.0.0.1", &addr2.sin_addr) <= 0) {
        std::cerr<<"Invalid address/ Address not supported"<<std::endl;
        return -1;
    }

    // connection of socket 2
    ns2 = connect(sock2, (struct sockaddr *) &addr2, sizeof(struct sockaddr_in));
    if (ns2 < 0) {
        std::cerr<<"cant connect to 127.0.0.1 with errno:"<<errno<<std::endl;
    }

    //socket 3
    if ( (sock3 = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        std::cerr<<"socket error"<<std::endl;
        exit(-1);
    }

    addr3.sin_family = AF_INET;
    addr3.sin_port = htons(3456);
    if (inet_pton(AF_INET, "127.0.0.1", &addr3.sin_addr) <= 0) {
        std::cerr<<"Invalid address/ Address not supported"<<std::endl;
        return -1;
    }

    // connection of socket 3
    ns3 = connect(sock3, (struct sockaddr *) &addr3, sizeof(struct sockaddr_in));
    if (ns3 < 0) {
        std::cerr<<"cant connect to 127.0.0.1 with errno:"<<errno<<std::endl;
    }

    //socket 4
    if ( (sock4 = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        std::cerr<<"socket error"<<std::endl;
        exit(-1);
    }

    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(4567);
    if (inet_pton(AF_INET, "127.0.0.1", &addr4.sin_addr) <= 0) {
        std::cerr<<"Invalid address/ Address not supported"<<std::endl;
        return -1;
    }

    // connection of socket 4
    ns4 = connect(sock4, (struct sockaddr *) &addr4, sizeof(struct sockaddr_in));
    if (ns4 < 0) {
        std::cerr<<"cant connect to 127.0.0.1 with errno:"<<errno<<std::endl;
    }
*/

    /*f1 = open("/dev/shm/dnsFlood",O_WRONLY);
    if(f1 < 0){
	std::cerr<<"failed to open /dev/shm/dnsFlood with errno: "<<errno<<std::endl;
    }*/
    /*f2 = open("/dev/shm/dnsAmplification",O_WRONLY);
    if(f2 < 0){
        std::cerr<<"failed to open /dev/shm/dnsAmplification with errno: "<<errno<<std::endl;
    }*/
    f3 = open("/dev/shm/sshBruteForce",O_WRONLY);
    if(f3 < 0){
        std::cerr<<"failed to open /dev/shm/sshBruteForce with errno: "<<errno<<std::endl;
    }
    /*f4 = open("/dev/shm/portScan",O_WRONLY);
    if(f4 < 0){
        std::cerr<<"failed to open /dev/shm/portScan with errno: "<<errno<<std::endl;
    }*/

    //msg_ptr = new data;

    // Start capture in async mode
    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, workers))
    {
    	std::cerr << "Couldn't start worker threads" << std::endl;
        return 1;
    }

    while (keepRunning)
    {
    }

}

L2FwdWorkerThread::L2FwdWorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice) :
    m_RxDevice(rxDevice), m_TxDevice(txDevice), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES)
{
}

bool L2FwdWorkerThread::run(uint32_t coreId)
{
    // Register coreId for this worker
    m_CoreId = coreId;
    m_Stop = false;

    // initialize a mbuf packet array of size 64
    pcpp::MBufRawPacket* mbufArr[64] = {};
    pthread_t p1,p2,p3,p4;
    // endless loop, until asking the thread to stop
    //key_t key = ftok("shmfile",65);
    //int shmid = shmget(key,sizeof(data),0666|IPC_CREAT);
    //ftruncate(shm_fd, sizeof(data));
    //void *ptr = mmap(0, sizeof(data), PROT_WRITE, MAP_SHARED, shm_fd, 0);
    //data *msg_ptr = (data *)shmat(shmid,(void*)0,0);
    while (!m_Stop)
    {
    // receive packets from RX device
    uint16_t numOfPackets = m_RxDevice->receivePackets(mbufArr, 64, 0);

    //if(!start){
    //        return true;
    //}
    count += numOfPackets;
    if (numOfPackets > 0)
    {
	msg_ptr = new data[numOfPackets];
	// debug statement
	if(firstpkt == 0){firstpkt = 1; clock_gettime(CLOCK_REALTIME,&temp_time1); printf("1st Pkt Recieved: %ld.%ld\n",temp_time1.tv_sec,temp_time1.tv_nsec);}
        //iovec iov = {(void *)msg_ptr,sizeof(data)*numOfPackets};
	if(enable == 0){
		enable = 1;
		clock_gettime(CLOCK_REALTIME,&current_time);
		/*clock_gettime(CLOCK_REALTIME,&temp_time1);
		arguments arg1 = {f1,&iov}, arg2 = {f2,&iov}, arg3 = {f3,&iov}, arg4 = {f4,&iov};
		pthread_create(&p1,NULL,send,&arg1);
                pthread_create(&p2,NULL,send,&arg2);
                pthread_create(&p3,NULL,send,&arg3);
                pthread_create(&p4,NULL,send,&arg4);
		pthread_detach(p1);
                pthread_detach(p2);
                pthread_detach(p3);
                pthread_detach(p4);*/
	}
	// send received packet on the TX device
        for(int i = 0; i < numOfPackets; i++){
		memcpy(msg_ptr[i].buff,mbufArr[i]->getRawData(),mbufArr[i]->getRawDataLen());
		msg_ptr[i].rawDataLen = mbufArr[i]->getRawDataLen();
		//std::cout<<msg.packet.rawDataLen<<std::endl;
		msg_ptr[i].timestamp = mbufArr[i]->getPacketTimeStamp();
		msg_ptr[i].layerType = mbufArr[i]->getLinkLayerType();

		//std::cout<<msg_ptr->rawDataLen*8<<std::endl;

		/*int temp = send(sock, msg_ptr, sizeof(data), 0);
		if (temp == -1) {
        	    std::cerr<<"Socket send error with errno: "<<errno<<std::endl;
        	    close(sock);
		    pid_t pid = getpid();
        	    kill(pid,SIGINT);
    		}*/
		//pcpp::RawPacket raw((const uint8_t*)msg_ptr[i].buff,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType);
		//pcpp::Packet p(&raw);
		//std::cout<<p.toString()<<std::endl;
		//std::cout<<"Count: "<<count<<" "<<p.getLayerOfType(pcpp::IPv4)->toString()<<std::endl;
		//count++;
		bits += msg_ptr->rawDataLen*8;
		//std::cout<<count<<std::endl;
		//std::cout<<"hit";
		//std::cout<<coreId<<": "<<counter<<std::endl;
	}

/*	//clock_gettime(CLOCK_REALTIME,&temp_time1);
	int temp = send(sock1, msg_ptr, sizeof(data)*numOfPackets, 0);
	//clock_gettime(CLOCK_REALTIME,&temp_time2);
        if (temp == -1) {
            std::cerr<<"sshbruteforce Socket send error with errno: "<<errno<<std::endl;
            close(sock1);
            pid_t pid = getpid();
            kill(pid,SIGINT);
        }
        temp = send(sock2, msg_ptr, sizeof(data)*numOfPackets, 0);
        if (temp == -1) {
            std::cerr<<"dnsflood Socket send error with errno: "<<errno<<std::endl;
            close(sock2);
            pid_t pid = getpid();
            kill(pid,SIGINT);
        }
        temp = send(sock3, msg_ptr, sizeof(data)*numOfPackets, 0);
        //clock_gettime(CLOCK_REALTIME,&temp_time2);
        if (temp == -1) {
            std::cerr<<"dnsAmplification Socket send error with errno: "<<errno<<std::endl;
            close(sock3);
            pid_t pid = getpid();
            kill(pid,SIGINT);
        }
        /*temp = send(sock4, msg_ptr, sizeof(data)*numOfPackets, 0);
        //clock_gettime(CLOCK_REALTIME,&temp_time2);
        if (temp == -1) {
            std::cerr<<"portscan Socket send error with errno: "<<errno<<std::endl;
            close(sock4);
            pid_t pid = getpid();
            kill(pid,SIGINT);
        }*/

	iovec iov = {(void *)msg_ptr,sizeof(data)*numOfPackets};
	/*for(int i = 0; i < numOfPackets; i++){
	    pcpp::RawPacket rawPacket((const uint8_t*)msg_ptr[i].buff,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType); //raw packet taken from pcap
            pcpp::Packet parsedPacket(&rawPacket); // making parsed packet from raw packet to extract information layer by layer
	    std::cout<<parsedPacket.toString()<<std::endl;
    	}*/
	int write;
    	/*write = vmsplice(f1,&iov,1,SPLICE_F_NONBLOCK);
    	if(write < 0){
	    if(errno == 11){continue;}
            std::cerr<<"Cant vmsplice to dnsFlood with errno"<<errno<<std::endl;
    	}*/
    	/*write = vmsplice(f2,&iov,1,SPLICE_F_NONBLOCK);
    	if(write < 0){
            if(errno == 11){continue;}
            std::cerr<<"Cant vmsplice to dnsAmplification with errno"<<errno<<std::endl;
    	}*/
    	write = vmsplice(f3,&iov,1,SPLICE_F_NONBLOCK);
    	if(write < 0){
            if(errno == 11){continue;}
            std::cerr<<"Cant vmsplice to sshBruteforce with errno"<<errno<<std::endl;
    	}
    	/*write = vmsplice(f4,&iov,1,SPLICE_F_NONBLOCK);
    	if(write < 0){
            if(errno == 11){continue;}
            std::cerr<<"Cant vmsplice to portScan with errno"<<errno<<std::endl;
    	}*/
	// debug statement
        if(count >= 24880){clock_gettime(CLOCK_REALTIME,&temp_time2); printf("%dth Pkt Recieved: %ld.%ld\n",count,temp_time2.tv_sec,temp_time2.tv_nsec);}
	/*for(int i = 0; i < numOfPackets; i++){
	    printf("Bytes of iov_base: %x\n", iov.iov_base);
            pcpp::RawPacket rawPacket((const uint8_t*)msg_ptr[i].buff,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType); //raw packet taken from pcap
            pcpp::Packet parsedPacket(&rawPacket); // making parsed packet from raw packet to extract information layer by layer
            std::cout<<parsedPacket.toString()<<std::endl;
        }*/
	//delete msg_ptr;
	//count+=numOfPackets;
    }
    }
    return true;
}

void L2FwdWorkerThread::stop()
{
    m_Stop = true;
}

uint32_t L2FwdWorkerThread::getCoreId() const
{
    return m_CoreId;
}


