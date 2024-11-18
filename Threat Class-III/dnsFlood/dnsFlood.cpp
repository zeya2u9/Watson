#include "PcapFileDevice.h"
#include "DnsLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <unistd.h>

#define ARR_SIZE 512

struct data{
      int seq;
      char buf[1500];
      int rawDataLen;
      timespec timestamp;
      pcpp::LinkLayerType layerType;
};

uint64_t count = 0, batch_count = 0;
short enable = 0, firstpkt = 0;
static unsigned int counter = 0;
static data *msg_ptr;
timespec c_time,f_time, debug_time_s, debug_time_f;
int fd;
unsigned long read_total = 0;

#define BURST 32

void handler(int sig){
	clock_gettime(CLOCK_REALTIME,&f_time);
        printf("\nShutting Down... with packets = %llu with data %lu and processing time = %llu.%llu\n",read_total/sizeof(data), read_total, f_time.tv_sec-c_time.tv_sec,f_time.tv_nsec-c_time.tv_nsec);
        delete msg_ptr;
        exit(0);
}

void* run(void *argp){
    long long* limit = (long long *)argp;
    std::vector<std::string> srcIP; // dest IP of the amplification
    std::unordered_map<std::string,int> floodScore; // map of dest IP and count of packets to it
    long long batch = 0;
    time_t current_time;
    while(1){
	if(enable == 0){
                enable = 1;
                clock_gettime(CLOCK_REALTIME,&c_time);
        }

	iovec iov = {(void *)msg_ptr,sizeof(data)*BURST};
	int read = vmsplice(fd,&iov,1,SPLICE_F_NONBLOCK);
	//int read = vmsplice(fd,&iov,1,0);
	//int rd = read(fd, (void *)msg_ptr, sizeof(data)*BURST);
	if(read < 0){
	    if(errno == 11){continue;}
	    std::cerr<<"read on /dev/shm/dnsFlood failed with errno: "<<errno<<std::endl;
	}
	if(read == 0){continue;}
	// debug statement
	if(firstpkt == 0){firstpkt = 1;clock_gettime(CLOCK_REALTIME,&debug_time_s);printf("1st Pkt: %ld:%ld\n",debug_time_s.tv_sec,debug_time_s.tv_nsec);}
	read_total += read;
	//std::cout<<"Bytes: "<<read<<" with packets: "<<read/sizeof(data)<<"with remainder: "<<read%sizeof(data)<<std::endl;
	for(int i = 0; i < read/sizeof(data); i++){
    	    count++;
	    //std::cout<<msg_ptr->seq<<std::endl;
	    //if(read < sizeof(data)){
	    //printf("data of iov base: %x\n", iov.iov_base);
	    pcpp::RawPacket rawPacket((const uint8_t*)msg_ptr[i].buf,msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType); //raw packet taken from pcap
	    pcpp::Packet parsedPacket(&rawPacket); // making parsed packet from raw packet to extract information layer by layer
        //std::cout<<msg_ptr->rawDataLen<<std::endl;
	    //std::cout<<parsedPacket.toString()<<std::endl;
	    //}
	    if (parsedPacket.isPacketOfType(pcpp::IPv4)){ // if the packet is of IPv4
		batch++;
		//printf("%d\n", parsedPacket.isPacketOfType(pcpp::IPv4));
		// printf("%p\n", parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPAddress());
		// std::cout << parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPAddress().toString().c_str();
	        if(strcmp(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPAddress().toString().c_str(),"103.25.231.79") == 0){
		    if(parsedPacket.isPacketOfType(pcpp::DNS)){
        	    	pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
            	        if(dnsLayer == NULL){continue;} // continue if the packet is not of dns
            	        if(dnsLayer->getDnsHeader()->queryOrResponse == 0){continue;} // if it is a dns query then do nothing
            	        else{ //if it is a dns response
			    if(dnsLayer->getAnswerCount() == 0){
                	    // check if it has an NX domain or not
                	    //batch++;
			    }
                	    floodScore[parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPAddress().toString()] = batch;
            	    	}
                    }
		}
	    if(count>=75493){clock_gettime(CLOCK_REALTIME,&debug_time_f);printf("%dth Pkt: %ld:%ld\n",count,debug_time_f.tv_sec,debug_time_f.tv_nsec);}
	    if(batch == *limit){
		batch_count++;
    	        // displaying all src IPs and how many % of dnsflood contrib
    	        for (auto x : floodScore){
                    std::cout<<"IP: "<<x.first<<"; %: "<<((float)x.second/batch)*100<<" in the batch of: "<<batch_count<<std::endl;
		    x.second = 0;
    	        }
	        batch = 0;
            }
        }
	}
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT,handler);
    if(argc<2){std::cerr<<"Usage: "<<argv[0]<<" Batch Size"<<std::endl;return -1;}
    long long batchsize = atoll(argv[1]);

    msg_ptr = new data[BURST];

    fd = open("/dev/shm/dnsFlood",O_RDONLY);
    pthread_t t1,t2,t3,t4,t5,t6,t7,t8;
    //run(&batchsize);
    pthread_create(&t1,NULL,run,&batchsize);
    /*pthread_create(&t2,NULL,run,&batchsize);
    pthread_create(&t3,NULL,run,&batchsize);
    pthread_create(&t4,NULL,run,&batchsize);
    pthread_create(&t5,NULL,run,&batchsize);
    pthread_create(&t6,NULL,run,&batchsize);
    pthread_create(&t7,NULL,run,&batchsize);
    pthread_create(&t8,NULL,run,&batchsize);*/
    pthread_join(t1,NULL);
    /*pthread_join(t2,NULL);
    pthread_join(t3,NULL);
    pthread_join(t4,NULL);
    pthread_join(t5,NULL);
    pthread_join(t6,NULL);
    pthread_join(t7,NULL);
    pthread_join(t8,NULL);*/
    return 0;
}
