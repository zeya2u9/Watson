#include <errno.h>
#include "PcapFileDevice.h"
#include "DnsLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define ARR_SIZE 512
#define BURST 32

struct data{
      int seq;
      char buf[1500];
      int rawDataLen;
      timespec timestamp;
      pcpp::LinkLayerType layerType;
};

static data* msg_ptr;
uint64_t count = 0, batch_count = 0;
timespec c_time,f_time, debug_time_s, debug_time_f;
short enable = 0, firstpkt = 0;
int fd;

void handler(int sig){
	clock_gettime(CLOCK_REALTIME,&f_time);
        printf("\nShutting Down... with packets = %llu and processing time = %llu.%llu\n",count,f_time.tv_sec-c_time.tv_sec,f_time.tv_nsec-c_time.tv_nsec);
        delete msg_ptr;
        exit(0);
}

void *run(void *argp){
    long long* limit = (long long *)argp;
    std::vector<std::string> destIP; // dest IP of the amplification
    std::vector<int> query; // transaction ID of query
    std::unordered_map<std::string,int> ampPacket; // map of dest IP and count of packets to it
    pcpp::Packet parsedPacket(100);
    long long counter = 0;
    while(1){
	if(enable == 0){
                enable = 1;
                clock_gettime(CLOCK_REALTIME,&c_time);
        }

	iovec iov = {(void *)msg_ptr,sizeof(data)*BURST};
	//memset(msg_ptr,0,sizeof(data));
	int read = vmsplice(fd,&iov,1,SPLICE_F_NONBLOCK);
	//int rd = read(fd, (void *)msg_ptr, sizeof(data)*BURST);
	if(read < 0){
	    if(errno == 11){continue;}
	    std::cerr<<"Cant vmsplice from /dev/shm/dnsAmplification with errno: "<<errno<<std::endl;
	}
	if(read == 0){continue;}
	// debug statement
	if(firstpkt == 0){firstpkt = 1;clock_gettime(CLOCK_REALTIME,&debug_time_s);printf("1st Pkt: %ld:%ld\n",debug_time_s.tv_sec,debug_time_s.tv_nsec);}
	count += read/sizeof(data);
	for(int i = 0; i < read/sizeof(data); i++){
            counter++;
            //std::cout<<msg_ptr->seq<<std::endl;
	    pcpp::RawPacket rawPacket((const uint8_t*)msg_ptr[i].buf,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType);
	    pcpp::Packet parsedPacket(&rawPacket);
	    //std::cout<<parsedPacket.toString()<<std::endl;
            if (parsedPacket.isPacketOfType(pcpp::IPv4)) // if the packet is of IPv4
            {
            	if(parsedPacket.isPacketOfType(pcpp::DNS)){
            	    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
            	    //if(dnsLayer == NULL){continue;} // continue if the packet is not of dns
            	    if(dnsLayer->getDnsHeader()->queryOrResponse == 0){query.push_back(be16toh(dnsLayer->getDnsHeader()->transactionID));} // if it is a dns query then push the transaction ID in the vector
            	    else{ //if it is a dns response
                    	// check if it has a transaction ID in the vector
                    	int key = be16toh(dnsLayer->getDnsHeader()->transactionID);
                    	std::vector<int>::iterator count = std::find(query.begin(), query.end(), key);
                    	if(count != query.end()){query.erase(count);} // if it has a transaction ID then simply erase that entry from the vector as the communication is complete
                    	else{ // if not, then it is possibly dnsAmplification
                   	    if(ampPacket.find(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPAddress().toString()) != ampPacket.end()){ampPacket[parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPAddress().toString()]++;}
		   	    else{ampPacket[parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPAddress().toString()] = 1;}
                    	}
                    }
                }
            }
	    //debug statement
            //if(count>=34244){clock_gettime(CLOCK_REALTIME,&debug_time_f);printf("%dth Pkt: %ld:%ld\n",count,debug_time_f.tv_sec,debug_time_f.tv_nsec);}
            if(counter == *limit){
		batch_count++;
                for(auto x : ampPacket){
		    if(x.second >= *limit){std::cout<<"IP: "<<x.first<<"; Count: "<<x.second<<" in the batch of: "<<batch_count<<std::endl;}
                }
                counter = 0;
            }
	}
    }
}

int main(int argc, char* argv[])
{
    //if less arguments
    signal(SIGINT,handler);
    if(argc<2){std::cout<<"Usage: "<<argv[0]<<" BatchSize"<<std::endl; return -1;}

    long long batchsize = atoll(argv[1]);

    fd = open("/dev/shm/dnsAmplification",O_RDONLY);


    msg_ptr = new data[BURST];

    pthread_t t1,t2,t3,t4,t5,t6,t7,t8;
    pthread_create(&t1,NULL,run,&batchsize);
    pthread_create(&t2,NULL,run,&batchsize);
    pthread_create(&t3,NULL,run,&batchsize);
    pthread_create(&t4,NULL,run,&batchsize);
    pthread_create(&t5,NULL,run,&batchsize);
    pthread_create(&t6,NULL,run,&batchsize);
    pthread_create(&t7,NULL,run,&batchsize);
    pthread_create(&t8,NULL,run,&batchsize);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    pthread_join(t3,NULL);
    pthread_join(t4,NULL);
    pthread_join(t5,NULL);
    pthread_join(t6,NULL);
    pthread_join(t7,NULL);
    pthread_join(t8,NULL);
    return 0;
}
