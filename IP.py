from PyQt5 import QtCore
from scapy.all import *


class ThreadSniffer(QtCore.QThread):
    connection = QtCore.pyqtSignal(list)

    def prepare_packet_input(self, source_ip, destination_ip, protocol):
        # 입력 형식에 맞게 패킷 데이터 변환
        packet_input = [source_ip, destination_ip, protocol]
        return packet_input

    def __init__(self, selected_iface):
        self.selected_iface = selected_iface
        super(ThreadSniffer, self).__init__()

    def packet_show(self, packet):
        Layer_packet = packet.getlayer(IP)
        Length_packet = str(len(packet))
        row_Data = [str(packet.time), str(Layer_packet.src), str(Layer_packet.dst)]

        packet_time = datetime.fromtimestamp(packet.time)
        formatted_time = packet_time.strftime("%Y.%m.%d.%H:%M:%S")
    
        row_Data = [formatted_time, str(Layer_packet.src), str(Layer_packet.dst)]

        if packet.haslayer(TCP):
            row_Data.append('TCP')
            # 포트 번호 정보를 가져오는 부분
            row_Data.append(str(packet[TCP].sport))
            row_Data.append(str(packet[TCP].dport))
        elif packet.haslayer(UDP):
            row_Data.append('UDP')
            # 포트 번호 정보를 가져오는 부분
            row_Data.append(str(packet[UDP].sport))
            row_Data.append(str(packet[UDP].dport))
        elif packet.haslayer(ICMP):
            row_Data.append('ICMP')
        elif packet.haslayer(DNS):
            row_Data.append('DNS')
            # 포트 번호 정보를 가져오는 부분
            row_Data.append(str(packet[DNS].sport))
            row_Data.append(str(packet[DNS].dport))
        else:
            row_Data.append('Unknown Type')

        # 패킷 페이로드 정보를 가져오는 부분
        payload = packet.getlayer(Raw)
        if payload:
            row_Data.append(payload.load.hex())
        else:
            row_Data.append('No Payload')

        row_Data.append(Length_packet)

        # 패킷 흐름 정보를 가져오는 부분
        row_Data.append(hexdump(packet, dump=True))

        self.connection.emit(row_Data)

    def run(self):
        packets = sniff(iface=self.selected_iface, filter="ip", prn=self.packet_show)

    def stop(self):
        self.Running = False
        self.terminate()
        self.wait(100)
