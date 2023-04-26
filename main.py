import sys
import os
import threading
import queue
from datetime import datetime
from scapy.all import *
from PyQt5 import QtWidgets, QtGui, QtCore
import numpy as np
import tensorflow as tf
from tensorflow import keras
from scapy.layers.inet import IP, TCP, UDP

class MainWindow(QtWidgets.QMainWindow):
    model_path = "my_model.h5"
    def __init__(self, model_path):
        super().__init__()
        
        self.model = keras.models.load_model(self.model_path)
        self.packet_queue = queue.Queue()
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.process_packets)
        self.timer.start(1000)  # 1초마다 처리
        self.init_ui()

    def init_ui(self):
        self.setGeometry(100, 100, 600, 400)
        self.setWindowTitle('Packet Sniffer')

        start_button = QtWidgets.QPushButton('Start Capture')
        stop_button = QtWidgets.QPushButton('Stop Capture')
        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Src Port', 'Dst Port', 'Length', 'Info'])

        layout = QtWidgets.QVBoxLayout()
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(start_button)
        button_layout.addWidget(stop_button)
        layout.addLayout(button_layout)
        layout.addWidget(self.table)

        central_widget = QtWidgets.QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def start_capture(self):
        t = threading.Thread(target=self.sniff_packets)
        t.start()

    def stop_capture(self):
        # 타이머 중지
        self.timer.stop()
        # sniff 함수에 stop_filter를 적용하여 패킷 수집을 중지함
        sniff(stop_filter=lambda x: True, count=0)
        # 큐에 None을 넣어 처리 쓰레드를 중지함
        self.packet_queue.put(None)

    def sniff_packets(self):
        sniff(prn=self.process_packet_wrapper, store=0)

    def sniff_packets(self):
         sniff(prn=self.process_packet_wrapper, store=0)
    
    def process_packet_wrapper(self, packet):
        if IP in packet:
            self.process_packet(packet)

    def process_packet(self, packet):
        if IP in packet:
            if TCP in packet:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, 'TCP', packet[TCP].sport, packet[TCP].dport, len(packet), packet.show(dump=True)]
            elif UDP in packet:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, 'UDP', packet[UDP].sport, packet[UDP].dport, len(packet), packet.show(dump=True)]
            else:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, packet[IP].proto, '-', '-', len(packet), packet.show(dump=True)]
                
            self.packet_queue.put(row)

            
    def process_packets(self):
        while not self.packet_queue.empty():
            row = self.packet_queue.get()
            if row is None:
                break
            self.add_packet(row)
            protocol = str(row[3])
            length = str(row[4])
            info = row[5]
            X = np.array([protocol, length, info])
            try:
                info = float(info)
                X = X.astype(np.float32)
                y = self.model.predict(X.reshape(1, -1))
                if y == 1:
                    self.show_warning()
            except ValueError:
                print("Could not convert string to float:", info)



    def predict_anomaly(self, X):
        self.model = keras.models.load_model(self.model_path)  # 모델을 매번 로드
        y = self.model.predict(X.reshape(1, -1))
        if y == 1:
            self.show_warning()
    def add_packet(self, row):
        n_rows = self.table.rowCount()
        self.table.setRowCount(n_rows + 1)
        for i, item in enumerate(row):
            self.table.setItem(n_rows, i, QtWidgets.QTableWidgetItem(item))

    def show_warning(self):
        QtWidgets.QMessageBox.warning(self, 'Warning', 'Possible attack detected!')
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow('my_model.h5')
    window.show()
    sys.exit(app.exec_())
