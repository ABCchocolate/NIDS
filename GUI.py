from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication
from time import sleep
import psutil, pickle
import IP
import Intrusion
from keras.models import load_model
import numpy as np
import logging
import sys
from datetime import datetime
import random
import matplotlib.pyplot as plt

class Packet:
    def __init__(self, sender, receiver, size):
        self.sender = sender
        self.receiver = receiver
        self.size = size

class Attacker:
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip
    
    def is_attacker_packet(self, packet):
        if packet.sender == self.attacker_ip:
            return True
        return False
    
class Network:
    def __init__(self):
        self.nodes = {}
        self.attacker = None
        self.detected_packets = [] 
    
    def add_node(self, node):
        if node in self.nodes:
            print("Node already exists in network.")
            return False
        self.nodes[node] = []
        return True
    
    def remove_node(self, node):
        if node not in self.nodes:
            print("Node not found in network.")
            return False
        del self.nodes[node]
        for key in self.nodes.keys():
            self.nodes[key] = [n for n in self.nodes[key] if n != node]
        return True
    
    def add_edge(self, node1, node2):
        if node1 not in self.nodes or node2 not in self.nodes:
            print("Nodes not found in network.")
            return False
        self.nodes[node1].append(node2)
        self.nodes[node2].append(node1)
        return True
    
    def remove_edge(self, node1, node2):
        if node1 not in self.nodes or node2 not in self.nodes:
            print("Nodes not found in network.")
            return False
        if node2 not in self.nodes[node1] or node1 not in self.nodes[node2]:
            print("Edge not found in network.")
            return False
        self.nodes[node1].remove(node2)
        self.nodes[node2].remove(node1)
        return True
    
    def set_attacker(self, attacker_ip):
        if attacker_ip not in self.nodes:
            print("Attacker IP not found in network.")
            return False
        self.attacker = Attacker(attacker_ip)
        self.Intrusion.load_model()
        return True
    
    def send_packet(self, packet):
        if packet.sender not in self.nodes or packet.receiver not in self.nodes:
            print("Nodes not found in network.")
            return False
        if self.attacker and self.attacker.is_attacker_packet(packet):
            print("Packet dropped (attacker packet).")
            return False
        
        intrusion_result = self.Intrusion.detect_intrusion(packet)
        if intrusion_result:
            print("Intrusion detected:", intrusion_result)
            self.detected_packets.append(packet)  # 탐지된 패킷을 detected_packets 리스트에 추가
            
        visited = []
        queue = [packet.sender]
        while queue:
            node = queue.pop(0)
            if node == packet.receiver:
                print("Packet received.")
                return True
            if node not in visited:
                visited.append(node)
                neighbors = self.nodes[node]
                for neighbor in neighbors:
                    queue.append(neighbor)
        print("Packet lost.")
        return False

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = UI_MainWindow()
        self.ui.setupUI(self)
        
        

class UI_MainWindow(object):

    def setupUI(self, MainWindow):
        MainWindow.setObjectName("MainWidow")
        MainWindow.resize(1094,771)
        MainWindow.setWindowFlags(QtCore.Qt.WindowCloseButtonHint | QtCore.Qt.WindowMinimizeButtonHint)
        
        self.CentralWidget = QtWidgets.QWidget(MainWindow)
        self.CentralWidget.setObjectName("CentralWidget")
        
        self.Packets = QtWidgets.QTableWidget(self.CentralWidget)
        self.Packets.setGeometry(QtCore.QRect(20,90,1051,251))
        self.Packets.setObjectName("Packets")
        
        logging.basicConfig(filename="sniffer.log", format='%(asctime)s %(message)s', filemode='a') 
        self.logger=logging.getLogger() 
        self.logger.setLevel(logging.DEBUG)
        self.logger.info('Interface started!')
        
        self.Filters = QtWidgets.QTextEdit(self.CentralWidget)
        self.Filters.setGeometry(QtCore.QRect(20,50,831,31))
        self.Filters.setObjectName("Filters")
        
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Packets.sizePolicy().hasHeightForWidth())
        
        
        self.Apply_Button = QtWidgets.QPushButton(self.CentralWidget)
        self.Apply_Button.setGeometry(QtCore.QRect(980, 50, 88, 31))
        self.Apply_Button.setObjectName("Apply_Button")
        
        
        self.Packets.setSizePolicy(sizePolicy)
        self.Packets.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.Packets.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.Packets.setLineWidth(1)
        self.Packets.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.Packets.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers) 
        self.Packets.setAlternatingRowColors(False)
        self.Packets.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        
        self.Packets.setRowCount(0)
        self.Packets.setColumnCount(6)
        
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets.setHorizontalHeaderItem(5, item)
        
        self.Packets.horizontalHeader().setCascadingSectionResizes(False)
        self.Packets.horizontalHeader().setDefaultSectionSize(160)
        self.Packets.horizontalHeader().setMinimumSectionSize(23)
        self.Packets.horizontalHeader().setSortIndicatorShown(False)
        self.Packets.horizontalHeader().setStretchLastSection(True)
        self.Packets.verticalHeader().setStretchLastSection(True)
        
        
        self.Info_Packet = QtWidgets.QTreeWidget(self.CentralWidget)
        self.Info_Packet.setGeometry(QtCore.QRect(20, 360, 1051, 191))
        self.Info_Packet.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.Info_Packet.setAlternatingRowColors(False)
        self.Info_Packet.setObjectName("Info_Packet")
        
        Item = QtWidgets.QTreeWidgetItem(self.Info_Packet)
        Item_0 = QtWidgets.QTreeWidgetItem(Item)
        
        font = QtGui.QFont()
        font.setPointSize(15)
        
        
        self.AI_Show = QtWidgets.QTextBrowser(self.CentralWidget)
        self.AI_Show.setGeometry(QtCore.QRect(20, 570, 1051, 131))
        self.AI_Show.setFont(font)
        self.AI_Show.setObjectName("AI_Show")
        
        
        self.InterFace = QtWidgets.QLabel(self.CentralWidget)
        self.InterFace.setGeometry(QtCore.QRect(20, 10, 131, 31))
        font.setPointSize(12)
        self.InterFace.setFont(font)
        self.InterFace.setObjectName("InterFace")
        
        
        self.Type_InterFace = QtWidgets.QComboBox(self.CentralWidget)
        self.Type_InterFace.setGeometry(QtCore.QRect(160, 10, 601, 31))
        self.Type_InterFace.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Type_InterFace.setAutoFillBackground(False)
        self.Type_InterFace.setObjectName("Type_InterFace")
        
        interfaces = psutil.net_if_addrs()
        interfaces = list(interfaces.keys())
        self.Type_InterFace.addItems(interfaces)
        
        
        self.captureB = QtWidgets.QPushButton(self.CentralWidget)
        self.captureB.setGeometry(QtCore.QRect(980, 10, 88, 31))
        self.captureB.setObjectName("CaptureB")
        
        self.Clear_PacketB = QtWidgets.QPushButton(self.CentralWidget)
        self.Clear_PacketB.setGeometry(QtCore.QRect(870, 50, 91, 31))
        self.FiltersButton = QtWidgets.QPushButton(self.CentralWidget)
        
        MainWindow.setCentralWidget(self.CentralWidget)
        
        
        self.Menu_Bar = QtWidgets.QMenuBar(MainWindow)
        self.Menu_Bar.setGeometry(QtCore.QRect(0, 0, 1094, 25))
        self.Menu_Bar.setObjectName("Menu_Bar")
        
        self.Menu_File = QtWidgets.QMenu(self.Menu_Bar)
        self.Menu_File.setObjectName("Menu_File")
        
        
        self.Menu_About = QtWidgets.QMenu(self.Menu_Bar)
        MainWindow.setMenuBar(self.Menu_Bar)
        self.Menu_About.setObjectName("Menu_About"
                                      )
        
        self.Status_Bar = QtWidgets.QStatusBar(MainWindow)
        MainWindow.setStatusBar(self.Status_Bar)
        self.Status_Bar.setObjectName("Status_Bar")
        
        self.Action_New = QtWidgets.QAction(MainWindow)
        self.Action_New.setObjectName("Action_New")
        
        self.Action_Open = QtWidgets.QAction(MainWindow)
        self.Action_Open.setObjectName("Action_Open")
        
        self.Action_Save = QtWidgets.QAction(MainWindow)
        self.Action_Save.setObjectName("Action_Save")
    
        self.Action_Exit = QtWidgets.QAction(MainWindow)
        self.Action_Exit.setObjectName("Action_Exit")
        
        self.Action_About = QtWidgets.QAction(MainWindow)
        self.Action_About.setObjectName("Action_About")
        
        self.Action_Instructions = QtWidgets.QAction(MainWindow)
        self.Action_Instructions.setObjectName("Action_Instructions")
        
        self.Menu_File.addAction(self.Action_New)
        self.Menu_File.addAction(self.Action_Open)
        self.Menu_File.addAction(self.Action_Save)
        self.Menu_File.addAction(self.Action_Exit)
        
        self.Menu_About.addAction(self.Action_Instructions)
        self.Menu_About.addAction(self.Action_About)
        
        self.Menu_Bar.addAction(self.Menu_File.menuAction())
        self.Menu_Bar.addAction(self.Menu_About.menuAction())
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
        self.Action_New.triggered.connect(self.new_btn_clicked)
        self.Action_Open.triggered.connect(self.Open_File)
        self.Action_Save.triggered.connect(self.Save_File)
        
        self.Action_Exit.triggered.connect(sys.exit)
        self.captureB.clicked.connect(self.capture_btn_clicked)
        
        self.Clear_PacketB.clicked.connect(self.displayData)
        
        self.Packets.cellClicked.connect(self.cell_clicked)
        self.Apply_Button.clicked.connect(self.Apply_btn_clicked)
        
        original_data = []
        current_row = 0
        model = None  # 가중치 모델을 저장할 변수 추가
    
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "짱짱걸들"))
        self.Filters.setPlaceholderText(_translate("MainWindow", "Filters"))
        self.Apply_Button.setText(_translate("MainWindow", "Apply"))
        
        #실제 받는 시간으로 고쳐야함
        item = self.Packets.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Time"))
        
        item = self.Packets.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Source"))
        item = self.Packets.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.Packets.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.Packets.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Length"))
        item = self.Packets.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Info"))
        
        __sortingEnabled = self.Info_Packet.isSortingEnabled()
        self.Info_Packet.setSortingEnabled(False)
        self.Info_Packet.topLevelItem(0).setText(0, _translate("MainWindow", "Full Packet Data"))
        self.Info_Packet.topLevelItem(0).child(0).setText(0, _translate("MainWindow", "Packet Data"))
        self.Info_Packet.setSortingEnabled(__sortingEnabled)
        
        self.InterFace.setText(_translate("MainWindow", "Choose Interface:"))
        
        self.Type_InterFace.setStatusTip(_translate("MainWindow", "Choose Interface for packets capture"))
        self.Type_InterFace.setItemText(0, _translate("MainWindow", "Select Interface for Capturing Packets"))
        
        self.captureB.setText(_translate("MainWindow", "Capture"))
        self.Clear_PacketB.setText(_translate("MainWindow", "Clear"))
        self.Menu_File.setTitle(_translate("MainWindow", "File"))

        self.Action_New.setText(_translate("MainWindow", "New"))
        self.Action_Open.setText(_translate("MainWindow", "Open"))
        self.Action_Save.setText(_translate("MainWindow", "Save"))
        self.Action_Save.setStatusTip(_translate("MainWindow", "Saves a file"))
        self.Action_Save.setShortcut(_translate("MainWindow", "Ctrl+S"))
        self.Action_Exit.setText(_translate("MainWindow", "Exit"))
        self.Action_Exit.setShortcut(_translate("MainWindow", "Alt+F4"))
        


    original_data = []
    current_row = 0
    
    def load_weights(self):
        weights_path = "weight\cnn_model.h5"  
        self.model = load_model(weights_path)
        self.model.summary()
        
    def Save_File(self):
        name,_ = QtWidgets.QFileDialog.getSaveFileName()
        '''if name:
            pickle.dump(self.original_data, open(name, "wb"))'''

    def Open_File(self):
        name,_ = QtWidgets.QFileDialog.getOpenFileName()
        if name:
            self.original_data = pickle.load(open(name, "rb"))
            self.displayData()
    
    def new_btn_clicked(self):
        while (self.Packets.rowCount() > 0):
            self.Packets.removeRow(0)
        self.original_data = []
        self.current_row = 0
        self.AI_Show.clear()
        self.Info_Packet.topLevelItem(0).child(0).setText(0, "Packet Data")
        
    def cell_clicked(self,row,column):
        self.AI_Show.clear()
        self.Info_Packet.topLevelItem(0).child(0).setText(0, self.original_data[row][7])
    
    def Apply_btn_clicked(self):
        if(self.Packets.rowCount()>0):
            if(self.Filters.toPlainText()==""):
                self.msg = QtWidgets.QMessageBox()
                self.msg.setIcon(QtWidgets.QMessageBox.Critical)
                self.msg.setWindowTitle("Missing input")
                self.msg.setText("No filter entered!")
                self.msg.exec_()
            else:
                search_filter = self.Filters.toPlainText()
                row_index_list = []
                count = 0
                for i in self.original_data:
                    if search_filter in i:
                        row_index_list.append(count)
                    count = count + 1
                self.displayFilter(row_index_list, self.original_data)
                
                # 탐지된 패킷들을 출력
                detected_packets_list = []
                for row_index in row_index_list:
                    detected_packets_list.append(self.original_data[row_index])
                
                # 출력을 위한 작업 수행 (예: 리스트에 추가, 출력 등)
                print("Detected packets:")
                for packet in detected_packets_list:
                    print(packet)
        else:
            self.msg = QtWidgets.QMessageBox()
            self.msg.setIcon(QtWidgets.QMessageBox.Critical)
            self.msg.setWindowTitle("No data!")
            self.msg.setText("Start a capture to apply filters.")
            self.msg.exec_()
            
    def storeData(self,Data):
        self.original_data.append(Data)
        self.addRowData(Data)

    def clearTableData(self):
        while (self.Packets.rowCount() > 0):
            self.Packets.removeRow(0)

    def clearData(self):
        self.original_data = []

    def clearCurrentRows(self):
        self.current_row = 0

    def displayData(self):
        self.Filters.clear()
        if(self.Packets.rowCount()>0):
            self.clearTableData()
            self.clearCurrentRows()
        for i in self.original_data:
            self.addRowData(i)

    def displayFilter(self,FilterList,DataList):
        self.clearTableData()
        self.clearCurrentRows()
        for i in FilterList:
            self.addRowData(DataList[i])
            
    def addRowData(self,packetData):
        self.Packets.insertRow(self.current_row)
        column_number = 0
        for s in packetData:
            if(column_number==6):
                column_number = column_number + 1
                break
            self.Packets.setItem(self.current_row,column_number,QtWidgets.QTableWidgetItem(s))
            column_number = column_number + 1
        self.current_row = self.current_row + 1
    capture_btn_state = 'Capture'
    
    def capture_btn_clicked(self):
        if self.capture_btn_state == 'Capture':
            interface_chosen = str(self.Type_InterFace.currentText())
            try:
                if interface_chosen == 'Select Interface for Capturing Packets':
                    self.msg = QtWidgets.QMessageBox()
                    self.msg.setIcon(QtWidgets.QMessageBox.Critical)
                    self.msg.setWindowTitle("Interface error!")
                    self.msg.setText("Not a valid capture interface! \nPlease choose a valid interface.")
                    self.msg.exec_()
                else:
                    self.captureB.setStyleSheet("background-color: red ; border:none")
                    self.capture_btn_state = 'Stop'
                    self.captureB.setText("Stop")

                    # Create an instance of ThreadSniffer
                    self.Thread = IP.ThreadSniffer(interface_chosen)
                    # Connect the connection signal to the storeData slot
                    self.Thread.connection.connect(self.storeData)
                    # Start the thread
                    self.Thread.start()

                    # Load the weights (add this code)
                    self.load_weights()

            except Exception as e:
                self.logger.error('Error starting packet capture: {}'.format(str(e)))
        else:
            self.captureB.setStyleSheet("")
            # Terminate the thread
            self.Thread.terminate()
            self.Thread.wait()
            self.captureB.setText("Capture")
            self.capture_btn_state = 'Capture'

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
