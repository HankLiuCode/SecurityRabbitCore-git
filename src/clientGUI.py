#status code 
#200 request success
#403 Forbidden (CSRF token not set) 
#500 internal server error
import requests
import sys
from PyQt5 import QtWidgets
from PyQt5 import QtCore
import settings
import os

class RabbitClient:
    def __init__(self):
        self.client=None
        self.uploadURL = 'http://127.0.0.1:8000/uploadxml/'
        self.csrftoken=""
    
    def startSession(self):
        self.client = requests.session()
        self.client.get(self.uploadURL)
        self.csrftoken=self.client.cookies['csrftoken']
        #print(r.status_code)
        #print(self.csrftoken)
    
    def uploadfile(self, to_upload):
        with open(to_upload,'rb') as xmlfile:
            self.client.post(
                self.uploadURL,
                files={'docfile':xmlfile},
                data={'csrfmiddlewaretoken':self.csrftoken}
                )
            #print(r2.status_code)
            #print(r2.content)
    
    def downloadfile(self):
        r = self.client.get('http://127.0.0.1:8000/downloadexe/srcore')
        pyfile = open("srcore.exe",'wb+')
        pyfile.write(r.content)
        pyfile.close()

        #print("downloadfile")
        #print(r.status_code)
    
    def closeSession(self):
        self.client.close()

class SecurityRabbitGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initGUI()
        self.rabbitClient = RabbitClient()

    def initGUI(self):
        self.scanType = "QuickScan"

        serverLabel = QtWidgets.QLabel('Server')
        directoryLabel = QtWidgets.QLabel('Directories')

        self.serverEdit = QtWidgets.QLineEdit()
        self.directoryEdit = QtWidgets.QLineEdit()

        quickScan = QtWidgets.QRadioButton("QuickScan")
        quickScan.scanType = "QuickScan"
        quickScan.setChecked(True)
        quickScan.toggled.connect(self.onClicked)

        normalScan = QtWidgets.QRadioButton("NormalScan")
        normalScan.scanType = "NormalScan"
        normalScan.toggled.connect(self.onClicked)

        deepScan = QtWidgets.QRadioButton("DeepScan")
        deepScan.scanType = "DeepScan"
        deepScan.toggled.connect(self.onClicked)

        progressInfo = QtWidgets.QLabel("adding file to pendingfile...")
        progressBar = QtWidgets.QProgressBar()

        scanBtn = QtWidgets.QPushButton('Start Scan')
        scanBtn.clicked.connect(self.startScan)

        gridlayout = QtWidgets.QGridLayout()
        gridlayout.addWidget(serverLabel, 1, 0)
        gridlayout.addWidget(self.serverEdit, 1, 1)
        gridlayout.addWidget(directoryLabel, 2, 0)
        gridlayout.addWidget(self.directoryEdit, 2, 1)

        gridlayout.addWidget(quickScan, 3, 0)
        gridlayout.addWidget(normalScan, 3, 1)
        gridlayout.addWidget(deepScan, 3, 2)

        gridlayout.addWidget(progressInfo, 4, 0, 1, 3)
        gridlayout.addWidget(progressBar, 5, 0, 1, 2)
        gridlayout.addWidget(scanBtn, 5, 2)

        self.setLayout(gridlayout)
        self.setWindowTitle('SecurityRabbit')
        self.show()

    def startScan(self):
        exefile = 'srcore'
        scanType = self.scanType
        serverIp = self.serverEdit.text()
        scanDirectory = self.directoryEdit.text()
        args = [serverIp, scanDirectory, scanType]

        self.startSession()
        self.downloadfile()
        self.process = QtCore.QProcess(self)
        self.process.execute(exefile, args)
        self.uploadfile()
        self.closeSession()
    

    def onClicked(self):
        radioButton = self.sender()
        if radioButton.isChecked():
            self.scanType = radioButton.scanType
    
    def startSession(self):
        self.rabbitClient.startSession()

    def uploadfile(self):
        filepath = os.path.join(settings.dataDir,'exeinfo.txt')
        self.rabbitClient.uploadfile(filepath)
    
    def downloadfile(self):
        self.rabbitClient.downloadfile()
    
    def closeSession(self):
        self.rabbitClient.closeSession()

if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    sr = SecurityRabbitGUI()
    app.exec_()





"""
Error:
This application failed to start because it could not find or load the Qt platform plugin "windows"
in "".
Reinstalling the application may fix this problem.

Solution:
COPY the
Continuum\Anaconda3\Library\plugins\platforms
folder to
Continuum\Anaconda3
"""