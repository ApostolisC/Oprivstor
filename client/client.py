import os
import sys
import shutil

import uuid
import getpass
import time
import json

from zipfile import ZipFile
import py7zr

import tempfile
from tabulate import tabulate

from pathvalidate import is_valid_filename, sanitize_filename

import socket
import threading

import subprocess

from PyQt5.QtWidgets import QWidget, QFileDialog, QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QGridLayout, QMessageBox

from PyQt5.QtGui import QFontMetrics, QFont

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

class Client():
    ##########################
    ####Cryptography
    def warmCryptographyEngine(self):
        self.cr = Cryptography()
        self.private_key,public_key, self.public_pem = self.cr.createRSAKeysWithPem()
    def warmDataBaseEngine(self):
        self.db = db("database")
    def exchangeKeysWithServer(self, main_connection=True):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((self.server,int(self.server_port)))

        s.send(("EXCHANGE %s"%('' if main_connection else "0")).encode())

        server_public_key = self.cr.getPublicFromPEM(self.getResponseFromServer(socket=s, exchange_mode=True))

        s.send(self.cr.createMessage(self.public_pem, server_public_key))


        if main_connection:
            self.s=s
            self.server_public_key=server_public_key

            response = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key).decode().split()

            self.greeting=' '.join(response[:-1])
            self.command_uuid = response[-1]
            return self.command_uuid
        else:
            s.recv(1024)
            return s, server_public_key



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
            r=socket.recv(1024*1024)
            size = self.cr.decryptMessage(bytes().fromhex(r.decode()), self.private_key)
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
        help.append(("",""))
        help.append(("jobs","To see all running actions"))
        help.append(("history","To see completed jobs"))
        print(tabulate(help, headers='firstrow'))
    ########################

    ####Compression
    def decompressStatusUpdate(self, running, job_id, th=False):
        if not th:
            a=threading.Thread(target=self.decompressStatusUpdate, args=(running, job_id, True,))
            a.daemon=True
            a.start()
            return
        p = ["\t|","\t/","\t-","\t\\"]
        i=0
        while running[0]:
            if i==4:
                i=0
            self.jobs[job_id][2] = p[i]
            i+=1
            time.sleep(0.1)

        self.jobs[job_id][2] = "Done"
        running[1]=True

    def compressFile(self,path,basepath, job_id):
        tmp='%s/%s.7z'%(self.settings.settings["temp-folder"],basepath)

        with py7zr.SevenZipFile(tmp, "w", password=str(self.master_passwd)) as a:
            running = [True,False]
            self.decompressStatusUpdate(running, job_id)
            a.writeall(path,basepath)

        running[0]=False
        while not running[1]:
            time.sleep(0.1)

        return '%s/%s.7z'%(self.settings.settings["temp-folder"],basepath)

    def decompressFile(self,path,dest, job_id):
        parent=os.path.dirname(dest)
        to_remove = path


        with py7zr.SevenZipFile(path,'r', password=str(self.master_passwd)) as a:
            running = [True,False]
            self.decompressStatusUpdate(running, job_id)

            a.extractall(path=os.path.dirname(path[:len(path)-3]))
            shutil.move(os.path.join(os.path.dirname(path),a.getnames()[0]),path[:-3])

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
                os.rename(path,os.path.join(os.path.dirname(path[:-3]),"%s%s"%(start,end[:-3])))
                path=os.path.join(os.path.dirname(path[:-3]),"%s%s"%(start,end[:-3]))

            self.jobs[job_id][3]=dest
            shutil.move(path,dest)

        os.remove(to_remove)
        running[0]=False
        while not running[1]:
            time.sleep(0.1)
    ########################

    ####Encryption
    def encryptFile(self, file, job_id):
        buffer_size=1024
        tmp_file="%s/%s.arc"%(self.settings.settings["temp-folder"],os.path.basename(file))
        with open(file, "rb") as f:
            size = os.path.getsize(file)
            with open(tmp_file,"wb") as encrypted_file:
                nonce = os.urandom(12)
                data = f.read(buffer_size)
                while data:
                    encrypted = self.cr.encryptFileChaCha20Poly1305(data, self.master_passwd, nonce)
                    encrypted_file.write(encrypted)
                    self.jobs[job_id][2]=str(int((f.tell()/size)*100))+"%"
                    data = f.read(buffer_size)

        self.jobs[job_id][2]="Done"
        time.sleep(1)
        return tmp_file, nonce.hex()

    def decryptFile(self,file, dest, nonce, job_id):
        nonce = bytes().fromhex(nonce)
        # Encrpyt will use 1024 buffer but chacha20poly1305 will generate and a tag of size 16
        # so 1024 + 16
        size = os.path.getsize(file)
        buffer_size=1040
        with open(file, "rb") as f:
            with open(dest,"wb") as decrypted_file:
                data = f.read(buffer_size)
                while data:
                    decrypted = self.cr.decryptChaCha20Poly1305(data, self.master_passwd, nonce)
                    decrypted_file.write(decrypted)
                    self.jobs[job_id][2]=str(int((f.tell()/size)*100))+"%"
                    data = f.read(buffer_size)

        os.remove(file)
        self.jobs[job_id][2]="Done"
        time.sleep(1)


    #####Download File
    def downloadFile(self,id, msg):
        try:
            try:
                file_info = self.db.getFileNameByID(id)[0]
            except IndexError:
                msg[0]="\n[!] Invalid ID."
                return
            filename, type = file_info[1:3]


            command = ("DOWNLOAD %s"%(filename.encode().hex()))
            message = "%s %s %s"%(self.command_uuid, self.username, command)

            s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

            s.send(self.cr.createMessage(message.encode(), server_public_key))

            result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

            if result=="1":
                return

            filename, file_size, compressed, nonce = self.cr.decryptMessage(self.getResponseFromServer(s),self.private_key).decode().split()


            filename = bytes().fromhex(filename).decode()
            file_size = int(file_size)

            path = os.path.join(self.settings.settings["download-folder"],filename)

            if compressed:
                tmp_file="%s/Archon/%s.7z"%(self.settings.settings["temp-folder"],os.path.basename(path))
            else:
                tmp_file="%s/Archon/%s.arc"%(self.settings.settings["temp-folder"],os.path.basename(path))

            s.send(self.cr.createMessage(b"0", self.server_public_key))


            progress = ["DOWNLOAD","(1/2) Downloading", "0%", path]
            job_id=self.getJobID()
            self.jobs[job_id] = progress

            msg[0]="\n[+] Downloading %s"% filename

            with open(tmp_file,"wb") as f:
                total=0
                buffer_size = 1024*1024*8
                buffer = s.recv(buffer_size)
                while buffer and total<file_size:
                    total+=len(buffer)
                    f.write(buffer)
                    self.jobs[job_id][2]=str(int((total/file_size)*100))+"%"
                    if total==file_size:
                        break
                    buffer = s.recv(buffer_size)
            s.close()
            if compressed=="True":
                self.jobs[job_id] = ["DOWNLOAD","(2/2) Decompressing - Decrypting", "-", path]
                self.decompressFile(tmp_file, path, job_id)
            else:
                self.jobs[job_id] = ["DOWNLOAD","(2/2) Decrypting","0%", path]
                self.decryptFile(tmp_file, path,nonce, job_id)

            self.jobs[job_id][1] = "Downloaded"
            self.old_jobs.append(self.jobs.pop(job_id))

        except Exception as e:
            print(e)
            self.jobs[job_id][1] = "ERROR"
            self.jobs[job_id][2] = "Incomplete"
            self.old_jobs.append(self.jobs.pop(job_id))
            #self.old_jobs.append(self.jobs.pop(job_id))


    #####Upload File
    def printUploadOptionsHelp(self):
        print()
        help=[["Command","Description"]]
        help.append(("help/h/?","Print this"))
        help.append(("",""))
        help.append(("name <name>","To upload the file under different name."))
        help.append(("compress <yes/no>","To compress the file before upload (default yes)."))
        help.append(("overwrite","<yes/no. Available if file already exists (default no)."))
        help.append(("",""))
        help.append(("show options","To print current settings for the upload."))
        help.append(("cancel","To return to the main menu."))
        help.append(("send","To send the file, begin the upload."))
        print(tabulate(help, headers='firstrow'))

    def printCurrentUploadSettings(self,compress, file, name, exists):
        print()
        help=[["Setting","Value"]]
        help.append(("Item to upload:",file))
        help.append(("Save under the name:",name))
        help.append(("Compress before upload:",str(compress)))
        if exists:
            help.append(("File already exists. Overwrite:","False"))
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
        os.system("clear")
        compress = True
        name = file
        exists = self.db.fileExists(os.path.basename(file))
        to_overwrite=False

        print("\n[+] File '%s' has been selected to be uploaded."%file)
        print("\n[Note]: Use help for upload options")
        self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name),exists)
        #self.printUploadOptionsHelp()
        ans=input("\n[Upload]: %s> "%file).split()
        while True:
            if ans[0]=="name":
                _name = ' '.join(ans[1:])
                _name = self.filterFileName(_name)
                if not _name:
                    print("[!] Invalid filename. Please try again.")
                else:
                    name = _name
                    exists = self.db.fileExists(os.path.basename(_name))
                    print("\nSave as -->",name)
            elif len(ans)==1:
                if ans[0] in ("help","?","h"):
                    self.printUploadOptionsHelp()
                elif ans[0]=="cancel":
                    return False
                elif ans[0]=="send":
                    if exists:
                        if not to_overwrite:
                            print("\n[-] Unable to upload file. File already exists. Please overwrite or upload under different name")
                        else:
                            break
                    else:
                        break
                else:
                    print("\nUnknown command.")
            elif len(ans)==2:
                if ans[0]=="compress":
                    if ans[1] not in ("yes","no"):
                        print("[-] Invalid compress option\n")
                    else:
                        compress = True if ans[1]=="yes" else False
                        print("\nCompress -->",compress)
                elif ans[0]=="show" and ans[1]=="options":
                    self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name), to_overwrite)
                elif ans[0]=="overwrite":
                    if exists:
                        if not ans[1] in ("yes","no"):
                            print("[-] Invalid overwrite options\n")
                        else:
                            to_overwrite = True if ans[1]=="yes" else False
                        print("overwrite:",to_overwrite)
                    else:
                        print("Unknown command.")
                else:
                    print("Unknown command.")
            else:
                print("Unknown command.")
            ans=input("\n[Upload]: %s> "%file).split()
        return (True, compress, name)

    def uploadFile(self, file_to_upload, options, msg):
        compress, name = options[1:]

        progress = ["UPLOAD","(1/2) Compressing - Encrypting" if compress else "(1/2) Encrypting", "0%", file_to_upload]
        job_id=self.getJobID()
        self.jobs[job_id] = progress

        msg[0]="\n[+] Uploading %s"% file_to_upload

        file_type="DIR" if os.path.isdir(file_to_upload) else "FILE"

        encoded_filename=os.path.basename(os.path.normpath(name)).encode().hex()

        command= ("UPLOAD %s %s %s"%(encoded_filename, "FILE", compress))
        message = "%s %s %s"%(self.command_uuid, self.username, command)

        s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

        s.send(self.cr.createMessage(message.encode(), server_public_key))

        result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

        if result=="1":
            print("\n[-] Action failed")
            s.close()
            return

        if file_type=="FILE":
            if compress:
                compressed_file = self.compressFile(file_to_upload,os.path.basename(file_to_upload), job_id)

                size = os.path.getsize(compressed_file)

                file_to_upload = compressed_file
                nonce=None
            else:
                file_to_upload, nonce = self.encryptFile(file_to_upload, job_id)
                size = os.path.getsize(file_to_upload)

        try:

            s.send(self.cr.createMessage(("%s %s"%(str(size), nonce)).encode(),self.server_public_key))


            self.jobs[job_id][1] = "Uploading"

            wait=s.recv(1024)
            with open(file_to_upload, "rb") as f:
                start=0
                buffer_size=1014*1024*2
                total=0
                while start<size:
                    s.sendfile(f,start,buffer_size)
                    start+=buffer_size
                    self.jobs[job_id][2]=str(int((start/size)*100))+"%"

                self.jobs[job_id][2]="..."
                self.jobs[job_id][1]="Retrieving Files"
                self.getFiles()
                self.jobs[job_id][1] = "Uploaded"
                self.jobs[job_id][2]="Done"
                time.sleep(1)
                self.old_jobs.append(self.jobs.pop(job_id))


        except BrokenPipeError:
            print("\n[!] Lost connection. Upload Canceled.")
            self.jobs[job_id][1] = "ERROR"
            self.jobs[job_id][2]="Incomplete"
            self.old_jobs.append(self.jobs.pop(job_id))
        return

    def uploadFilePreload(self, msg):
        file_to_upload = self.getFile()
        if not file_to_upload:
            return
        options = self.getUploadFileOptions(file_to_upload)
        if not options:
            msg[0]="\n[-] exAbort."
            return

        a=threading.Thread(target=self.uploadFile, args=(file_to_upload, options, msg))
        a.daemon=True
        a.start()

    ########################
    def printOldJobs(self):
        print("\nOld records:\n")
        status=[["Action","Status","Progress", "Path"]]
        for job in self.old_jobs:
            status.append(job)
        print(tabulate(status, headers="firstrow"))

    def printJobs(self):
        status=[["Action","Status","Progress", "Path"]]
        for job in self.jobs:
            status.append(self.jobs[job])
        print(tabulate(status, headers="firstrow"))

    def printJobsLoop(self):
        try:
            while self.jobs:
                os.system("clear")
                self.printJobs()
                time.sleep(0.1)
        except KeyboardInterrupt:
            os.system("clear")
            self.printJobs()
            return
        finally:
            os.system("clear")
            self.printJobs()
            print("\nNo running commands.")
    ########################

    #####Parse file
    def getFile(self):
        #app = QApplication(sys.argv)
        fd = FileDialog()
        return fd.getResult()
    #########################

    ##get new job id
    def getJobID(self):
        self.jobID+=1
        return self.jobID


    def __init__(self,server,port):
        self.server, self.server_port = server, port
        self.settings = ReadSettings()
        self.authenticated=False


        self.jobID=0
        self.jobs = {}
        self.old_jobs=[]

        self.warmCryptographyEngine()
        self.warmDataBaseEngine()
        self.exchangeKeysWithServer()

        self.window = Panel(self.greeting, self)

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
                        msg=[""]
                        self.uploadFilePreload(msg)

                        while not msg[0]:
                            time.sleep(0.1)
                        print(msg[0])


                    elif command[0]=="jobs":
                        self.printJobsLoop()
                    elif command[0]=="history":
                        self.printOldJobs()
                    else:
                        print("\nUnknown command.")
                elif len(command)==2:
                    pass
                    if command[0]=="download":
                        try:
                            msg=[""]
                            a=threading.Thread(target=self.downloadFile,args=(int(command[1]),msg,))
                            a.daemon=True
                            a.start()
                            while not msg[0]:
                                time.sleep(0.1)
                            print(msg[0])

                        except ValueError:
                            print("\n[!] Invalid id")
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
    app=QApplication(sys.argv)
    def __init__(self,greeting, client, action="Login"):
        super(Panel, self).__init__()
        self.username=None
        self.ready=False
        self.client=client

        size=self.app.primaryScreen()

        screen = size.size()
        self.screen_width, self.screen_height = screen.width(), screen.height()

        self.setObjectName("MainWindow")
        self.action = action

        self.setWindowTitle("ARCHON %s"%action.upper())

        self.setFixedWidth(300)

        nameLabel = QLabel('Username',self)
        self.nameLineEdit = QLineEdit(self)
        nameLabel.setBuddy(self.nameLineEdit)

        passwordLabel = QLabel('&Password',self)
        self.passwordLineEdit = QLineEdit(self)
        self.passwordLineEdit.setEchoMode(QLineEdit.Password)
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

        self.show()
        self.app.exec_()


    def changeAction(self,text):
        self.setWindowTitle("F3G %s"%text.upper())
        self.btnOK.setText(text)
        self.action=text

    def Exit(self):
        self.close()

    def validateCredentials(self):
        self.username = self.nameLineEdit.text()
        if not self.username:
            QMessageBox.critical(self, 'Action Failed', "Username can't be null", buttons=QMessageBox.Ok,)

        elif not self.passwordLineEdit.text():
            QMessageBox.critical(self, 'Action Failed', "Password can't be null", buttons=QMessageBox.Ok,)

        else:
            result = self.client.LoginPanel(self.username, self.passwordLineEdit.text(), self.action)
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
