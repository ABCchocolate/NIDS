from scapy.all import *
import csv

# 패킷 캡처 콜백 함수
def packet_callback(packet):
    # 필요한 패킷 정보 추출
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    pkt_len = len(packet)

    # 추출한 패킷 정보를 CSV 파일에 저장
    with open('packet_capture.csv', mode='a') as file:
        writer = csv.writer(file)
        writer.writerow([src_ip, dst_ip, src_port, dst_port, pkt_len])

# CSV 파일 헤더 추가
with open('packet_capture.csv', mode='w') as file:
    writer = csv.writer(file)
    writer.writerow(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Packet Length'])

# 패킷 캡처
sniff(prn=packet_callback, filter='tcp', count=10)
