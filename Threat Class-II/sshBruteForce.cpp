#include "PcapFileDevice.h"
#include "Layer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "SSHLayer.h"
#include "Packet.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <tuple>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BURST 32

struct data{
      int seq;
      char buf[1500];
      int rawDataLen;
      timespec timestamp;
      pcpp::LinkLayerType layerType;
};

static data* msg_ptr;
uint64_t counter = 0,counter_temp = 0, batch_count = 0;
timespec c_time,f_time, debug_time_s, debug_time_f;
short enable = 0, firstpkt = 0;
int fd;
std::map<std::tuple<std::string,int,std::string>,std::tuple<time_t,char,unsigned long>> sshBFScore; // map of (src IP src port dest IP)as key, (timestamp, tcp flag and count of packets to it) as values
std::map<std::string,unsigned long> result_temp, result; // map of attacker IP and number of connections
pthread_mutex_t lock1, lock2;
const char* target = "192.168.22.171"; // our target which we need to detect against

void *run(void *argp){
    time_t current_time;
    long long* limit = (long long *)argp;

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
		    std::cerr<<"Cant read on /dev/shm/sshBruteForce with errno: "<<errno<<std::endl;
		}
		if(read == 0){continue;}
		// debug statement
        	if(firstpkt == 0){firstpkt = 1;clock_gettime(CLOCK_REALTIME,&debug_time_s);printf("1st Pkt: %ld.%ld\n",debug_time_s.tv_sec,debug_time_s.tv_nsec);}
		counter_temp += read/sizeof(data);
		//std::thread threads[read/sizeof(data)];
		for(int i = 0; i < read/sizeof(data); i++){
	        //std::cout<<msg_ptr->seq<<std::endl;
		    pcpp::RawPacket rawPacket((const uint8_t*)&(msg_ptr[i].buf),msg_ptr[i].rawDataLen,msg_ptr[i].timestamp,0,msg_ptr[i].layerType);
	        pcpp::Packet parsedPacket(&rawPacket); // making parsed packet from raw packet to extract information layer by layer
		    //std::cout << parsedPacket.toString() << std::endl;
		    if (parsedPacket.isPacketOfType(pcpp::IPv4)){ // if the packet is of IPv4
				int temp1 = strncmp(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString().c_str(), target, 14);
			    int temp2 = strncmp(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString().c_str(), target, 14);
			    int temp3 = 0;
			    if(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString() != parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString()){temp3 = 1;}
			    //std::cout<<temp1<<temp2<<temp3<<std::endl;
			    int tempfinal = ((temp1 == 0) && (temp2 != 0) && (temp3 == 1));
			    //std::cout<<"((
				if(parsedPacket.isPacketOfType(pcpp::TCP)){
					if(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort() != 22 && parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getDstPort() != 22){continue;} // continue if the packet is not of ssh
					else{
						if((parsedPacket.isPacketOfType(pcpp::SSH))){continue;}
						else{
							current_time = rawPacket.getPacketTimeStamp().tv_sec;
							//std::cout<<parsedPacket.toString()<<std::endl;
							//std::cout<<parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->synFlag<<std::endl;
							if((parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->synFlag == 1) && (parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->ackFlag == 0)){ // if it is a syn tcp packet from outside to the target
								//std::cout<<"hit"<<std::endl;
								// if the flow entry doesnt exist in the map then create it along with value (timstamp,flag,count) defaulting to (timestamp,SYN,0)
								pthread_mutex_lock(&lock1);
								if(sshBFScore.find(std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())) == sshBFScore.end()){
									sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())] = std::make_tuple(current_time,'S',0);
								}
								// if it exists then for obvious reasons with the same port the earlier connection would have been closed hence set the flag to SYN again
								else{
									std::get<0>(sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())]) = current_time;
									std::get<1>(sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())]) = 'S';
								}
								pthread_mutex_unlock(&lock1);
							}
							//std::cout<<"hit"<<std::endl;
							if(parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->finFlag == 1){ // if it is a fin tcp packet from outside to the target
								counter++; // increment the counter
								// set the flag value to FIN in the map
								pthread_mutex_lock(&lock1);
								std::get<1>(sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())]) = 'F';
								// check the timestamp, if its <= 12 then its definetly ssh bruteforce hence do count++ in the value
								if(current_time - std::get<0>(sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())]) <= 12){
									std::get<2>(sshBFScore[std::make_tuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString(),parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getSrcPort(),parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString())])++;
									//std::cout<<"hit"<<std::endl;
									// a loop to convert the map of flows to a map of IPs since we dont care about ports during identification
									for(auto x : sshBFScore){
										//std::cout<<"hit"<<std::endl;
										if(current_time - std::get<0>(x.second) <=  12){
											//pthread_mutex_lock(&lock2);
											if(result_temp.find(std::get<0>(x.first)) == result_temp.end()){ result_temp[std::get<0>(x.first)] = 0; }
											else{ result_temp[std::get<0>(x.first)]++; }
											//pthread_mutex_unlock(&lock2);
										}
									}
								}
								pthread_mutex_unlock(&lock1);
							}
						}
					}
				}
			}
			else{
				continue;
			}
			//debug statement
	                if(counter_temp>=24880){clock_gettime(CLOCK_REALTIME,&debug_time_f);printf("%dth Pkt: %ld.%ld\n",counter_temp,debug_time_f.tv_sec,debug_time_f.tv_nsec);}
			//std::cout<<counter<<" "<<*limit<<std::endl;
			if(counter >= (*limit)){
				batch_count++;
				// displaying all attacaker IPs and total attempts
				for(auto x : result_temp){
					if(result.find(x.first) == result.end()){
					    result[x.first] = x.second;
					}
					else{
					    result[x.first] = (x.second > result[x.first])?x.second:result[x.first];
					}
				    x.second = 0;
				}
				counter = 0;
			}
		}
    }
}

void handler(int sig){
        clock_gettime(CLOCK_REALTIME,&f_time);
        for(auto x : result){
        	std::cout<<"IP: "<<x.first<<" with total BruteForce attempts of: "<<batch_count<<std::endl;
        }
        printf("\nShutting Down... with packets = %llu and processing time = %llu.%llu\n",counter_temp,f_time.tv_sec-c_time.tv_sec,f_time.tv_nsec-c_time.tv_nsec);
        delete msg_ptr;
	exit(0);
}

int main(int argc, char* argv[])
{
    signal(SIGINT,handler);
    //if less arguments
    if(argc<2){std::cerr<<"Usage: "<<argv[0]<<" BatchSize"<<std::endl; return -1;}

    if(strlen(argv[1]) >= 19){
        std::cerr<<"Too long number for Batch Size"<<std::endl;
        std::cerr<<"18 digits Maximum"<<std::endl;
        return -1;
    }
    char batch[18];
    char *end;
    strcpy(batch,argv[1]);
    long long batchsize = atoll(argv[1]);

    fd = open("/dev/shm/sshBruteForce",O_RDONLY);
    if(fd < 0){
	std::cerr<<"Cant open /dev/shm/sshBruteForce with errno: "<<errno<<std::endl;
    }
    msg_ptr = new data[BURST];

    pthread_t t1,t2,t3,t4,t5,t6,t7,t8;
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
