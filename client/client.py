import os
import sys
import shutil

import uuid
import getpass

import json

from zipfile import ZipFile
import py7zr

import tempfile
from tabulate import tabulate


from pathvalidate import is_valid_filename, sanitize_filename
from alive_progress import alive_bar

import socket
import threading

from PyQt5.QtWidgets import QWidget, QFileDialog, QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QGridLayout, QMessageBox

from PyQt5.QtGui import QFontMetrics

from Cryptography import Cryptography
from database import DataBase as db


class FileDialog(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Archon - File Manager'
        self.left = 10
        self.top = 10
        self.width = 1040
        self.height = 580
        self.files=None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.openFileNameDialog()
        #self.openFileNamesDialog()
        #self.saveFileDialog()

        self.show()

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        #options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"File to Upload", "","All Files (*)", options=options)
        self.files=fileName
    def openFileNamesDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        files, _ = QFileDialog.getOpenFileNames(self,"QFileDialog.getOpenFileNames()", "","All Files (*);;Python Files (*.py)", options=options)
        self.files = files

    def saveFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(self,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)
        self.files=fileName

    def getResult(self):
        return self.files

class ReadSettings():
    def getSettings(self):
        return self.settings
    def getTMPFolder(self):
        return self.settings["temp-folder"]

    def createDefaultSettings(self):
        with open(".settings","w") as f:
            settings = {}
            settings["download-folder"] = "%s"%os.path.join(os.path.expanduser('~'), "ARCHON Downloads")
            settings["temp-folder"] = "%s"%tempfile.gettempdir()
            settings["storage-limit"] = "None"
            settings["second-storage-limit"] = "None"
            settings["storage-usage-warning"] = {"mode": "per", "value": "100"}
            f.write(json.dumps(settings))

    def __init__(self):
        if not os.path.exists(".settings"):
            self.createDefaultSettings()
        self.settings = json.loads(open(".settings","r").read())
        self.download_folder = self.settings["download-folder"]
        self.tmp_folder = self.settings["temp-folder"]
        self.storage_limit = self.settings["storage-limit"]
        self.storage_limit_warning = self.settings["storage-usage-warning"]
        for item in (self.download_folder, self.tmp_folder):
            if not os.path.exists(item):
                os.mkdir(item)
        self.total_storage, self.used_storage, self.free_storage = self.getStorage()

    def examineStorage(self):
        self.archon_usage = self.getArchonDownloadsSize()
        self.archon_free_to_use = self.storage_limit-self.archon_usage

    def getArchonDownloadsSize(self):
        size = 0
        for path, dirs, files in os.walk(os.path.join(os.path.expanduser('~'), "ARCHON Downloads")):
            for f in files:
                fp = os.path.join(path, f)
                size += os.path.getsize(fp)
        return size
    def getStorage(self):
        total, used, free = shutil.disk_usage("/")
        return total // (2**30), used // (2**30), free // (2**30)



class Client:
    ##########################
    ####Cryptography
    def warmCryptographyEngine(self):
        self.cr = Cryptography()
        self.private_key,public_key, self.public_pem = self.cr.createRSAKeysWithPem()
    def warmDataBaseEngine(self):
        self.db = db("database")
    def exchangeKeysWithServer(self):
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.s.connect((self.server,int(self.server_port)))
        self.s.send(b"EXCHANGE")
        self.server_public_key = self.cr.getPublicFromPEM(self.getResponseFromServer(exchange_mode=True))
        self.s.send(self.cr.createMessage(self.public_pem, self.server_public_key))
        response = self.getResponseFromServer()
        greeting=self.cr.decryptMessage(response, self.private_key).decode()
        self.greeting=greeting
    ##########################

    ####LOGIN & SIGNUP SECTION
    def getCredentials(self):
        username = input("\nUsername: ")
        password = getpass.getpass("Password: ")
        return username, password
    def LoginPanel(self, username, password, action):
        try:
            command = ("%s %s %s"%(action.upper().encode().hex(),username.encode().hex(),password.encode().hex())).encode()
            enc_msg=self.cr.createMessage(command, self.server_public_key)
            self.s.send(enc_msg)
            response = self.cr.decryptMessage(self.getResponseFromServer(),self.private_key).decode()


            if response[0]=='0':
                print("in")
                self.username = username
                self.authenticated=True
                os.system("clear")
                print("[Server]:",self.greeting)
                print("\n"+response[1:])
                print("\nUsername:", username)
            else:
                return response[1:]

            if self.authenticated:
                self.s.send(self.cr.createMessage(b"0", self.server_public_key))
                self.master_passwd = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key)

            return self.authenticated

        except KeyboardInterrupt:
            sys.exit()
    ###########################

    ####GET RESPONSE FROM SERVER
    def getResponseFromServer(self, socket=False, exchange_mode=False, items=None):
        if not socket: socket=self.s
        if not exchange_mode:
            size = self.cr.decryptMessage(bytes().fromhex(socket.recv(1024*1024).decode()), self.private_key)
            to_send = self.cr.createMessage(b"0", self.server_public_key)
        else:
            size = bytes().fromhex(socket.recv(1024).decode())
            to_send=b"0"
        socket.send(to_send)
        size = int(size.decode())
        total=0
        data=b""
        while total<size:
            buffer = socket.recv(1024*1024)
            total+=len(buffer)
            data+=buffer

        return data

    ###GET FILES
    def getFiles(self,command=None):
        if not command:
            command = ("LS %s"%(b".".hex())).encode()
        enc_msg=self.cr.createMessage(command, self.server_public_key)
        self.s.send(enc_msg)
        response = self.cr.decryptMessage(self.getResponseFromServer(self.s),self.private_key)
        self.loadFilesToDatabase(response)
    #########################

    ####Store files to database
    def loadFilesToDatabase(self, data):
        self.db.purgeDatabase()
        data=data.decode().split()
        counter=1
        while data:
            item=[counter]
            for j in range(6):
                item.append(bytes().fromhex(data.pop(0)).decode().strip())
            self.db.addFile(item)
            counter+=1
    ##########################
    ###Print Database
    def printDatabase(self, records=None):
        print("\nRecords:\n")
        if not records:
            records = self.db.getFiles()
        records.insert(0, ['ID','Name','Type','Size','Modification Date','Creation Date', "Compressed"])
        print(tabulate(records, headers='firstrow'))
    #########################

    ####Usage manual
    def printHelp(self):
        print()
        help=[["Command","Description"]]
        help.append(("help/h/?","Print this"))
        help.append(("exit","Exit the program"))
        help.append(("",""))
        help.append(("download <id>","To download a file"))
        help.append(("upload","To upload a file"))
        help.append(("",""))
        help.append(("files","To list files on server"))
        help.append(("sort <parameter> <order>","files command sorted by (parameters: name, type, size, mod_date, create_date) and (order: a, d (asc, desc))"))
        print(tabulate(help, headers='firstrow'))
    ########################

    ####Compression
    def compressFile(self,path,basepath):
        tmp='%s/%s.7z'%(self.settings.settings["temp-folder"],basepath)
        print("\n[+] Compressing and Encrypting to:",tmp)


        with py7zr.SevenZipFile(tmp, "w", password=str(self.master_passwd)) as a:
            with alive_bar(bar=None, spinner = "circles") as bar:
                bar.title="Compressing-Encrypting item"
                bar()
                a.writeall(path,basepath)

        return '%s/%s.7z'%(self.settings.settings["temp-folder"],basepath)

    def decompressFile(self,path,dest):
        print("\n[+] Decompressing and Decrypting to:",dest)
        parent=os.path.dirname(dest)

        with py7zr.SevenZipFile(path,'r', password=str(self.master_passwd)) as a:
            with alive_bar(bar=None, spinner = "circles") as bar:
                bar.title="Decompressing-Decrypting item"
                bar()
            a.extractall(path=os.path.dirname(path[:len(path)-3]))

        path=path[:-3]
        path2=os.path.basename(path)
        index=path2.index(".")
        start=path2[:index]
        end=path2[index:]
        counter=0
        while os.path.exists(dest):
            if counter==0:
                start=start+"(1)"
            else:
                start=start[:-(len(str(counter))+1)]+str(counter)+")"
            counter+=1
            path2="%s%s"%(start,end)
            dest=os.path.join(parent,path2)
            print(dest)
            os.rename(path,os.path.join(os.path.dirname(path[:-3]),"%s%s"%(start,end[:-3])))
            path=os.path.join(os.path.dirname(path[:-3]),"%s%s"%(start,end[:-3]))
        shutil.move(path,dest)
    ########################

    ####Encryption
    def encryptFile(self, file):
        print("\n[+] Encrypting %s..."%file)
        buffer_size=1024
        tmp_file="%s/%s.arc"%(self.settings.settings["temp-folder"],os.path.basename(file))
        with open(file, "rb") as f:
            with open(tmp_file,"wb") as encrypted_file:
                nonce = os.urandom(12)
                data = f.read(buffer_size)
                with alive_bar(os.path.getsize(file), spinner = "circles") as bar:
                    bar.text("Encrypting...")
                    while data:
                        encrypted = self.cr.encryptFileChaCha20Poly1305(data, self.master_passwd, nonce)
                        encrypted_file.write(encrypted)
                        bar(buffer_size)
                        data = f.read(buffer_size)
        return tmp_file, nonce.hex()

    def decryptFile(self,file, dest, nonce):
        print("\n[+] Decrypting file...")
        nonce = bytes().fromhex(nonce)
        print(nonce,len(nonce))
        buffer_size=1040
        with open(file, "rb") as f:
            with open(dest,"wb") as decrypted_file:
                with alive_bar(os.path.getsize(file), spinner = "circles") as bar:
                    bar.text("Decrypting...")
                    data = f.read(buffer_size)
                    while data:
                        decrypted = self.cr.decryptChaCha20Poly1305(data, self.master_passwd, nonce)
                        decrypted_file.write(decrypted)
                        bar(buffer_size)
                        data = f.read(buffer_size)

    #####Download File
    def downloadFile(self,id):
        file_info = self.db.getFileNameByID(id)[0]
        filename, type = file_info[1:3]

        command = ("DOWNLOAD %s"%(filename.encode().hex())).encode()

        enc_msg=self.cr.createMessage(command, self.server_public_key)
        self.s.send(enc_msg)
        command_id = self.cr.decryptMessage(self.getResponseFromServer(self.s),self.private_key).decode()

        if not command_id:
            return
        if command_id[0]=="!":
            print("\n[!] Action Failed:", command_id[1:])
            return

        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((sys.argv[1],int(sys.argv[2])))
        s.send(b"PASS "+self.cr.createMessage(("%s %s"%(self.username, command_id)).encode(), self.server_public_key))

        data = self.cr.decryptMessage(self.getResponseFromServer(s),self.private_key).decode().split()
        filename = ' '.join(data[:-3])
        file_size = int(data[-3])
        compressed = data[-2]
        nonce = data[-1]


        path = os.path.join(self.settings.settings["download-folder"],filename)

        if compressed:
            tmp_file="%s/%s.7z"%(self.settings.settings["temp-folder"],os.path.basename(path))
        else:
            tmp_file="%s/%s.arc"%(self.settings.settings["temp-folder"],os.path.basename(path))

        s.send(self.cr.createMessage(b"0", self.server_public_key))

        with open(tmp_file,"wb") as f:
            print("\n[+] Downloading to:",path)
            total=0
            with alive_bar(file_size) as bar:
                bar.text="Downloading..."
                buffer_size = 1024*1024*8
                buffer = s.recv(buffer_size)
                while buffer and total<file_size:
                    total+=len(buffer)
                    f.write(buffer)

                    bar(len(buffer))
                    if total==file_size:
                        break
                    buffer = s.recv(buffer_size)
        print("\n[+] Download completed")
        s.close()
        if compressed=="True":
            self.decompressFile(tmp_file, path)
        else:
            self.decryptFile(tmp_file, path,nonce)

    ########################

    #####Upload File
    def printUploadOptionsHelp(self):
        print()
        help=[["Command","Description"]]
        help.append(("help/h/?","Print this"))
        help.append(("compress <yes/no>","To compress the file before upload (default yes)."))
        help.append(("name <name>","To upload the file under different name."))
        help.append(("show options","To print current settings for the upload."))
        help.append(("cancel","To return to the main menu."))
        help.append(("send","To send the file, begin the upload."))
        print(tabulate(help, headers='firstrow'))

    def printCurrentUploadSettings(self,compress, file, name):
        print()
        help=[["Setting","Value"]]
        help.append(("Item to upload:",file))
        help.append(("Save under the name:",name))
        help.append(("Compress before upload:",str(compress)))
        print(tabulate(help, headers='firstrow'))

    def filterFileName(self, file):
        valid = is_valid_filename(file)
        if not valid:
            print("\n[>] Invalid Filename. sanitizing...")
            sanitized = sanitize_filename
            if not is_valid_filename(sanitized):
                print("[-] Failed.")
                return False
            else:
                return sanitized
        return file

    def getUploadFileOptions(self, file):
        compress = True
        name = file
        print("\n[+] File '%s' has been selected to be uploaded."%file)
        print("\n[Note]: Use help for upload options")
        self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name))
        #self.printUploadOptionsHelp()
        ans=input("\n[Upload]: %s> "%file).split()
        if not ans:ans=['']
        while ans[0] not in ("cancel", "send"):
            if ans[0]=="name":
                _name = ' '.join(ans[1:])
                _name = self.filterFileName(_name)
                if not _name:
                    print("[!] Invalid filename. Please try again.")
                else:
                    name = _name
                    print("\nSave as -->",name)
            elif len(ans)==1:
                if ans[0] in ("help","?","h"):
                    self.printUploadOptionsHelp()
                elif ans[0]=="cancel":
                    return False
                elif ans[0]=="send":
                    break
                else:
                    print("Unknown command.")
            elif len(ans)==2:
                if ans[0]=="compress":
                    if ans[1] not in ("yes","no"):
                        print("[-] Invalid compress option\n")
                    else:
                        compress = True if ans[1]=="yes" else False
                        print("\nCompress -->",compress)
                elif ans[0]=="show" and ans[1]=="options":
                    self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name))
                else:
                    print("Unknown command.")
            else:
                print("Unknown command.")
            ans=input("\n[Upload]: %s> "%file).split()
            if not ans:ans=['']
        return (True, compress, name)

    def uploadFile(self):
        file_to_upload = self.getFile()
        if not file_to_upload:
            return
        options = self.getUploadFileOptions(file_to_upload)
        if not options: return
        compress, name = options[1:]

        file_type="DIR" if os.path.isdir(file_to_upload) else "FILE"
        if file_type=="FILE":
            if compress:
                compressed_file = self.compressFile(file_to_upload,os.path.basename(file_to_upload))
                print()

                size = os.path.getsize(compressed_file)

                file_to_upload = compressed_file
                nonce=None
            else:
                file_to_upload, nonce = self.encryptFile(file_to_upload)
                #nonce=None
                size = os.path.getsize(file_to_upload)

        encoded_filename=os.path.basename(os.path.normpath(name)).encode().hex()
        command= ("UPLOAD %s %s %s %s %s"%(encoded_filename, str(size), "FILE", compress, "False" if compress else nonce)).encode()
        enc_msg=self.cr.createMessage(command, self.server_public_key)
        self.s.send(enc_msg)
        response = self.cr.decryptMessage(self.getResponseFromServer(self.s),self.private_key).decode()

        if not response:
            return
        if response[0]=="!":
            print("\n[!] Action Failed:", response[1:])
            return
        else:
            command_id = response

        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.server,int(self.server_port)))
            s.send(b"PASS "+self.cr.createMessage(("%s %s"%(self.username, command_id)).encode(), self.server_public_key))

            response = self.cr.decryptMessage(s.recv(1024*10), self.private_key).decode()
            if response=="1":
                ans=input("[>] File already exists. Overwrite? [y/n]: ").lower()
                if ans not in ("y","yes"):
                    print("[-] Abort.")
                    s.send(self.cr.createMessage(b"1",self.server_public_key))
                    return
                s.send(self.cr.createMessage(b"0",self.server_public_key))
            else:
                s.send(self.cr.createMessage(b"0",self.server_public_key))

            print("\n[+] Initializing upload")
            with open(file_to_upload, "rb") as f:
                start=0
                buffer_size=1014*1024*2
                total=0
                with alive_bar(size) as bar:
                    bar.text="Uploading..."
                    while start<size:
                        s.sendfile(f,start,buffer_size)
                        start+=buffer_size
                        bar(buffer_size if start<size else size-(start-buffer_size))

                print("[+] Upload completed.")
        except BrokenPipeError:
            print("\n[!] Lost connection. Upload Canceled.")
        return

    #########################
    #####Parse file
    def getFile(self):
        #app = QApplication(sys.argv)
        fd = FileDialog()
        return fd.getResult()
    #########################

    def __init__(self,server,port):
        self.server, self.server_port = server, port
        self.settings = ReadSettings()
        self.authenticated=False

        self.warmCryptographyEngine()
        self.warmDataBaseEngine()
        self.exchangeKeysWithServer()

        app=QApplication(sys.argv)
        size=app.primaryScreen()
        window = Panel(self.greeting, self, size)
        window.show()
        app.exec_()

        if not self.authenticated: sys.exit()

        self.getFiles()
        self.printDatabase()

        while True:
            try:
                command=input("\nArchon> ").lower().split()
                if len(command)==1:
                    if command[0] in ("help","h","?"):
                        self.printHelp()
                    elif command[0]=="exit":
                        sys.exit()
                    elif command[0]=="files":
                        self.getFiles()
                        self.printDatabase()
                    elif command[0]=="upload":
                        self.uploadFile()
                    else:
                        print("\nUnknown command.")
                elif len(command)==2:
                    pass
                    if command[0]=="download":
                        self.downloadFile(int(command[1]))
                    else:
                        print("\nUnknown command.")
                elif len(command)==3:
                    if command[0]=="sort":
                        type = command[1]
                        order=command[2]
                        if type not in ("name","type","size","mod_date","create_date"):
                            print("\n[!] Invalid parameter:",type)
                            continue
                        if order not in ("a","d"):
                            print("\n[!] Invalid order:",order)
                            continue
                        type=type[0].upper()+type[1:]
                        order = "ASC" if order=="a" else "DESC"
                        if "_" in type:
                            type=type.split("_")
                            type=type[0]+type[1][0].upper()+type[1][1:]

                        fun = getattr(self.db, "getFilesBy%s"%type)
                        self.printDatabase(fun(order))
                    else:
                        print("\nUnknown command.")
                elif len(command)==0:
                    continue
                else:
                    print("\nUnknown command.")
            except KeyboardInterrupt:
                pass

class Panel(QMainWindow):
    authenticated=False
    def __init__(self,greeting, client, size, action="Login"):
        super(Panel, self).__init__()
        self.username=None
        self.password=None
        self.ready=False
        self.client=client

        screen = size.size()
        self.screen_width, self.screen_height = screen.width(), screen.height()

        self.setObjectName("MainWindow")
        self.action = action

        self.setWindowTitle("ARCHON %s"%action.upper())

        self.setFixedWidth(300)

        nameLabel = QLabel('Username',self)
        self.nameLineEdit = QLineEdit(self)
        self.nameLineEdit.setText("apostolis")
        nameLabel.setBuddy(self.nameLineEdit)

        passwordLabel = QLabel('&Password',self)
        self.passwordLineEdit = QLineEdit(self)
        self.passwordLineEdit.setEchoMode(QLineEdit.Password)
        self.passwordLineEdit.setText("apostolis")
        passwordLabel.setBuddy(self.passwordLineEdit)

        self.serverMessage = QTextEdit()
        self.serverMessage.setReadOnly(True)

        self.btnOK = QPushButton('&%s'%action, self)
        btnCancel = QPushButton('&Cancel')
        self.btnOK.clicked.connect(self.validateCredentials)
        btnCancel.clicked.connect(self.Exit)

        actionBox = QComboBox(self)
        actionBox.addItems(["Login","SignUp"])
        actionBox.activated[str].connect(self.changeAction)

        mainLayout = QGridLayout(self)
        mainLayout.addWidget(nameLabel,0,0)
        mainLayout.addWidget(self.nameLineEdit,0,1,1,2)

        mainLayout.addWidget(passwordLabel,1,0)
        mainLayout.addWidget(self.passwordLineEdit,1,1,1,2)

        mainLayout.addWidget(actionBox,2,0)
        mainLayout.addWidget(self.btnOK,2,1)
        mainLayout.addWidget(btnCancel,2,2)
        mainLayout.addWidget(self.serverMessage,3,0,3,3)

        wid = QWidget(self)
        wid.setLayout(mainLayout)
        self.setCentralWidget(wid)

        self.changeText("Connecting to Server...")
        self.changeText(greeting)


        self.move(int(self.screen_width/2)-int(self.width()/2),int(self.screen_height/2)-int(self.height()/4))

    def changeAction(self,text):
        self.setWindowTitle("F3G %s"%text.upper())
        self.btnOK.setText(text)
        self.action=text

    def Exit(self):
        self.close()

    def validateCredentials(self):
        self.username, self.password=self.nameLineEdit.text(),self.passwordLineEdit.text()
        if not self.username:
            QMessageBox.critical(self, 'Action Failed', "Username can't be null", buttons=QMessageBox.Ok,)

        elif not self.password:
            QMessageBox.critical(self, 'Action Failed', "Password can't be null", buttons=QMessageBox.Ok,)

        else:
            result = self.client.LoginPanel(self.username, self.password, self.action)
            if result==True:
                self.Exit()
            else:
                QMessageBox.critical(self, 'Action Failed', result, buttons=QMessageBox.Ok,)


    def changeText(self,server_message):
        self.serverMessage.setText(server_message)

        font = self.serverMessage.document().defaultFont()
        fontMetrics = QFontMetrics(font)
        textSize=fontMetrics.size(0, self.serverMessage.toPlainText())
        self.serverMessage.setMaximumSize(self.serverMessage.width(), textSize.height()+20)

        self.move(int(self.screen_width/2)-int(self.width()/2),int(self.screen_height/2)-int(self.height()/2))




client=Client(sys.argv[1],sys.argv[2])
