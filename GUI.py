#PyQt5 GUI를 만들기 위해 필요한 Qt5 어플리케이션 프레임워크에 대한 파이썬 버전
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
feature=["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
          "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_rootss_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","s","num_file_creations","num_shells",
          "num_acceerror_rate","srv_serror_rate",
          "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count", 
          "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
          "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

#클래스 이름을 패킷이라고 하며 
class Packet:
    def __init__(self, sender, receiver, size):
        self.sender = sender
        self.receiver = receiver
        self.size = size
        self.packet_data = []



class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = UI_MainWindow()
        self.ui.setupUI(self)
        self.attackers = []
        self.ui.Add_Attacker.clicked.connect(self.add_attacker)
        self.ui.Apply_Button.clicked.connect(self.detect_attackers)
        
    import random

    def add_attacker(self):
        with open("./Attacker.txt", "r") as f:
            lines = f.readlines()
            attacker_data = random.choice(lines).strip().split(',')

            # 필요한 필드 인덱스
            source_index = 2
            destination_index = 3
            protocol_index = 1
            length_index = 19
            info_index = 41  # 마지막 필드

            # 필드 추출
            source = attacker_data[source_index]
            destination = attacker_data[destination_index]
            protocol = attacker_data[protocol_index]
            length = attacker_data[length_index]
            info = attacker_data[info_index]

            self.attackers.append((source, destination, protocol, length, info))
            print("Added attacker:", (source, destination, protocol, length, info))
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # 패킷 데이터를 테이블의 마지막 행에 추가
            row_count = self.ui.Packets.rowCount()
            self.ui.Packets.insertRow(row_count)

            # 필드 값을 테이블에 설정
            self.ui.Packets.setItem(row_count, 0, QtWidgets.QTableWidgetItem(current_time))
            self.ui.Packets.setItem(row_count, 1, QtWidgets.QTableWidgetItem(source))
            self.ui.Packets.setItem(row_count, 2, QtWidgets.QTableWidgetItem(destination))
            self.ui.Packets.setItem(row_count, 3, QtWidgets.QTableWidgetItem(protocol))
            self.ui.Packets.setItem(row_count, 4, QtWidgets.QTableWidgetItem(length))
            self.ui.Packets.setItem(row_count, 5, QtWidgets.QTableWidgetItem(info))

            if info != "normal":
                for col in range(self.ui.Packets.columnCount()):
                    item = self.ui.Packets.item(row_count, col)
                    item.setBackground(QtGui.QColor(255, 0, 0))


           

    def detect_attackers(self):
        model = load_model("./weight/final_model.h5")
        for row in range(self.ui.Packets.rowCount()):
            source_ip = self.ui.Packets.item(row, 1).text()
            if source_ip in self.attackers:
                packet_data = []
                for col in range(self.ui.Packets.columnCount()):
                    item = self.ui.Packets.item(row, col)
                    item.setBackground(QtGui.QColor(255, 0, 0))
                    packet_data.append(float(item.text()))

                # 패킷 데이터를 모델에 입력하여 공격 여부를 예측
                prediction = model.predict([packet_data])
                if prediction[0] > 0.5:
                    print("Detected attack from source IP:", source_ip)
        
# Pyqt5 패키지로 GUI 창을 만들 때 사용되는 QWidget, QDialog, QMainWindow 클래스 3형제들
#Main Windows는 상태바랑 메뉴바 같은 걸 넣을 수 있어 말그대로 Win32 API로 Application 만드는 거랑 똑같다
#PyQt5로 GUI 구성시 윈도우 창을 생성하는 클래스
class UI_MainWindow(object):
    
   #mainwindow를 이용하여 윈도우 만들기_메인 윈도우 값
    #setupUI는 self 와 mainwindow 다중 속성을 갖는다.
    #최상위 위젯으로 메뉴바, 도구 모음, 상태바등이 포함된 미리 정의된 레이아웃을 가지고 있다
    def setupUI(self, MainWindow):
        #메인윈도우값, 메인 윈도우명 MainWindow 라고 정함
        MainWindow.setObjectName("MainWidow")
        #사이즈
        MainWindow.resize(1094,771)
        #python, pyqt5로 만든 프로그램을 항상 맨 위위에 있게 하려면 setWind 2owFlags(Qt.WindowStaysOnTopHint)를 추가
        #최대화 버튼을 '비활성화'
        MainWindow.setWindowFlags(QtCore.Qt.WindowCloseButtonHint | QtCore.Qt.WindowMinimizeButtonHint)
        
        #중앙위젯 =  QWidget을 딱 한마디로 설명하면 버튼, input 위젯 같은 다양한 위젯들을 올려놓을 수 있는 사각형의 영역
        #특징으로는 Main Window와 다르게 상단의 메뉴창과 하단의 상태창을 추가할 수 없다.
        self.CentralWidget = QtWidgets.QWidget(MainWindow)
        #centralwidget = centralwidget
        self.CentralWidget.setObjectName("CentralWidget")
        
        #TableWidget행과열로 구성
        self.Packets = QtWidgets.QTableWidget(self.CentralWidget)
        self.Packets.setGeometry(QtCore.QRect(20,90,1051,251))
        self.Packets.setObjectName("Packets")
        
        #프로그램 캡쳐를 시작했을 때 시작된 시간과 메시지를 log 로 작성
        logging.basicConfig(filename="sniffer.log", format='%(asctime)s %(message)s', filemode='a') 
        self.logger=logging.getLogger() 
        self.logger.setLevel(logging.DEBUG)
        self.logger.info('Interface started!')
        
        #QTextEdit 텍스트 입력 "Filters" 설정부분
        self.Filters = QtWidgets.QTextEdit(self.CentralWidget)
        self.Filters.setGeometry(QtCore.QRect(20,50,831,31))
        self.Filters.setObjectName("Filters")
        
        
        self.Add_Attacker = QtWidgets.QPushButton(self.CentralWidget)
        self.Add_Attacker.setGeometry(QtCore.QRect(870, 10, 88, 31))
        self.Add_Attacker.setObjectName("Add_Attacker")
        
        self.Add_Attacker.clicked.connect(MainWindow.add_attacker)
        #SizePolicy 기본 사이즈에 대한 정책
        #sizePolicy 로 생성되는 무언가를 일괄적으로 레이아웃의 크기에 따라 가로, 세로 방향의 크기가 커지게 된다.
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
        
         #최상단 목록self.packetInfo 받아와서 다시 item_1에 넣어서 출력
        Item = QtWidgets.QTreeWidgetItem(self.Info_Packet)
        Item_0 = QtWidgets.QTreeWidgetItem(Item)
        
        font = QtGui.QFont()
        font.setPointSize(15)
        
        
        ##self.AI_Show = QtWidgets.QTextBrowser(self.CentralWidget)
        ##self.AI_Show.setGeometry(QtCore.QRect(20, 570, 1051, 131))
        ##self.AI_Show.setFont(font)
        ##self.AI_Show.setObjectName("AI_Show")
        
        #Choose Interface: 쓰는 부분
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
        
        #캡쳐버튼
        self.captureB = QtWidgets.QPushButton(self.CentralWidget)
        self.captureB.setGeometry(QtCore.QRect(980, 10, 88, 31))
        self.captureB.setObjectName("CaptureB")
        
        #지우기버튼
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
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "짱짱걸들"))
        self.Filters.setPlaceholderText(_translate("MainWindow", "Filters"))
        self.Apply_Button.setText(_translate("MainWindow", "Apply"))
        
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
        
        self.Add_Attacker.setText(_translate("MainWindow","Add_Attacker"))
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
        weights_path = "./weight/final_model.h5"  
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
        #패킷을 받아옵니다.
        while (self.Packets.rowCount() > 0):
            self.Packets.removeRow(0)
        self.original_data = []
        self.current_row = 0
        self.AI_Show.clear()
        self.Info_Packet.topLevelItem(0).child(0).setText(0, "Packet Data")
        
    def cell_clicked(self,row,column):
        #self.AI_Show.clear()
        self.Info_Packet.topLevelItem(0).child(0).setText(0, self.original_data[row][7])
    
    #패킷 허용 눌렀을 때
    def Apply_btn_clicked(self):
        if(self.Packets.rowCount()>0):
            #패킷 필터링
            if(self.Filters.toPlainText()==""):
                self.msg = QtWidgets.QMessageBox()
                self.msg.setIcon(QtWidgets.QMessageBox.Critical)
                #패킷유형 안 눌렀을때
                self.msg.setWindowTitle("Missing input")
                #필터창에 안 썼을 때
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

                    # add_attacker 실행
                    self.add_attacker()

                    # detect_attackers 실행
                    self.detect_attackers()

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
    mainWindow = MainWindow()
    mainWindow.show()
    mainWindow.detect_attackers()  # detect_attackers 함수 호출
    sys.exit(app.exec_())
