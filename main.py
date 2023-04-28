import sys
import os
import threading
import queue
from datetime import datetime
from scapy.all import *
from PyQt5 import QtWidgets, QtGui, QtCore
import io
import random
import numpy as np
import tensorflow as tf
from tensorflow import keras
from scapy.layers.inet import IP, TCP, UDP, Ether
from sklearn.preprocessing import StandardScaler
import base64


class MainWindow(QtWidgets.QMainWindow):
    model_path = "my_model.h5"
    packet_processing_limit = 100  # process up to 100 packets at a time

    def __init__(self, model_path):
        super().__init__()
        self.scaler = StandardScaler()
        self.model = keras.models.load_model(self.model_path)
        self.packet_queue = queue.Queue()
        self.is_running = True
        self.init_ui()
        

    def init_ui(self):
        self.setGeometry(100, 100, 600, 400)
        self.setWindowTitle('Packet Sniffer')

        start_button = QtWidgets.QPushButton('Start Capture')
        stop_button = QtWidgets.QPushButton('Stop Capture')
        add_attack_button = QtWidgets.QPushButton('Add Attack Packet')

        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)
        add_attack_button.clicked.connect(self.add_attack_packet)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ['Time', 'Source', 'Destination', 'Protocol', 'Src Port', 'Dst Port', 'Length', 'Info'])

        layout = QtWidgets.QVBoxLayout()
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(start_button)
        button_layout.addWidget(stop_button)
        button_layout.addWidget(add_attack_button)
        layout.addLayout(button_layout)
        layout.addWidget(self.table)

        central_widget = QtWidgets.QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.process_packets)
        self.timer.start(100)  # call process_packets every 100ms

    def start_capture(self):
        t = threading.Thread(target=self.sniff_packets)
        t.start()

    def stop_capture(self):
        self.timer.stop()
        # Stop sniffing packets
        sniff(prn=lambda x: None, timeout=1)
        # Stop packet processing thread
        self.packet_queue.put(None)

    def sniff_packets(self):
        sniff(prn=self.process_packet_wrapper, store=0)

    def process_packet_wrapper(self, packet):
        if IP in packet:
            self.process_packet(packet)

    def process_packet(self, packet):
        if IP in packet:
            if TCP in packet:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, 'TCP', str(packet[TCP].sport), str(packet[TCP].dport), str(len(packet)), packet.summary()]
            elif UDP in packet:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, 'UDP', str(packet[UDP].sport), str(packet[UDP].dport), str(len(packet)), packet.summary()]
            else:
                row = [str(datetime.now()), packet[IP].src, packet[IP].dst, packet[IP].proto, '-', '-', str(len(packet)), packet.summary()]
        else:
            row = [str(datetime.now()), '-', '-', '-', '-', '-', str(len(packet)), packet.summary()]

        protocol = row[3]
        length = row[6]
        info = row[7]
        # Extract numbers from packet summary
        try:
            info_num = [num for num in info if num.isdigit()]
            if info_num:
                info_str = ''.join(info_num)
                X = np.array([protocol, length, info_str]).astype(np.float32)
                self.predict_anomaly(X)
        except ValueError as e:
            print("Could not convert to float in packet summary:", e)
        except TypeError as e:
            print("Could not convert to float in packet summary:", e)

        self.packet_queue.put(row)

    def process_packets(self):
        while not self.packet_queue.empty():
            row = self.packet_queue.get()
            if row is None:
                break
            try:
                self.add_packet(row)
                protocol = str(row[3])
                length = str(row[6])
                info = row[7]
                X = np.array([protocol, length, info])
                if info and any(char.isdigit() for char in info):
                    info = float(''.join(filter(str.isdigit, info)))
                    X[2] = info
                    X = X.astype(np.float32)
                    y = self.model.predict(X.reshape(1, -1))
                    if y > 0.5:
                        self.show_warning()
            except Exception as e:
                print("Error processing packet:", e)
                
                
    def predict_anomaly(self, packet):
        packet_array = np.array(packet)
        normalized_packet = self.scaler.transform(packet_array.reshape(1, -1))
        prediction = self.model.predict(normalized_packet)
        return prediction

    def add_packet(self, row):
        n_rows = self.table.rowCount()
        self.table.setRowCount(n_rows + 1)
        for i, item in enumerate(row):
            self.table.setItem(n_rows, i, QtWidgets.QTableWidgetItem(item))
            
    def show_warning(self):
        msg_box = QtWidgets.QMessageBox()
        msg_box.setIcon(QtWidgets.QMessageBox.Warning)
        msg_box.setWindowTitle("Anomaly Detected")
        msg_box.setText("Anomaly Detected!")
        msg_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg_box.exec_()
        
   
    def add_attack_packet(self):
        row = [str(datetime.now()), "192.168.0.1", "192.168.0.2", "TCP", "1234", "5678", "100", "Attack packet"]
        self.add_packet(row)
        n_rows = self.table.rowCount()
        for i in range(self.table.columnCount()):
            self.table.item(n_rows - 1, i).setBackground(QtGui.QColor(255, 0, 0))



        
    def extract_attackers():
        attack_ips = set()
        with open("KDDTest+.txt", "r") as f:
            for line in f:
                line = line.strip()
                if ",0" in line:  # normal connection
                    continue
                # extract attacker IP address
                attacker_ip = line.split(",")[0]
                attack_ips.add(attacker_ip)
        return list(attack_ips)
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow('my_model.h5')
    window.show()
    sys.exit(app.exec_())
