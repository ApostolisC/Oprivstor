import os
import sys
import shutil

import gzip

import uuid
import getpass
import time
import json


import tempfile
from tabulate import tabulate

from pathvalidate import is_valid_filename, sanitize_filename

import socket
import threading


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
            settings["temp-folder"] = "%s"%os.path.realpath(tempfile.gettempdir())
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
                self.username = username
                self.authenticated=True
                os.system(self.clear)
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

    ###DELETE FILE ON SERVER
    def deleteFile(self, id):
        file = self.db.getFileNameByID(id)[0][1]
        if not file:
            print("\n[-] File doesn't exist.")
            return
        else:
            encoded_filename=os.path.basename(file).encode().hex()
            message = "%s %s DELETE %s"%(self.command_uuid, self.username, encoded_filename)

            s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

            s.send(self.cr.createMessage(message.encode(), server_public_key))

            result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

            s.close()
            if result[0]=="1":
                print(result[1:])
            elif result==1:
                print("\n[!] File doesn't exist")
            else:
                print("\n[+] File '%s' deleted."%file)
                self.getFiles()
            return

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
        print("\nRetrieving files:\n")
        if not records:
            records = self.db.getFiles()
        if not records:
            print("[-] No records.")
            return
        records.insert(0, ['ID','Name','Type','Size','Modification Date','Creation Date', "Compressed"])
        print(tabulate(records, headers='firstrow',tablefmt="fancy_grid",maxcolwidths=[None, 25,None,None,None,None,None]))
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
        help.append(("delete <id>","To delete a file"))
        help.append(("",""))
        help.append(("files","To list files on server"))
        help.append(("sort <parameter> <order>","files command sorted by (parameters: name, type, size, mod_date, create_date) and (order: a, d (asc, desc))"))
        help.append(("",""))
        help.append(("jobs","To see all running actions"))
        help.append(("cancel <id>","To cancel a job with <id>"))
        help.append(("history","To see completed jobs"))
        print(tabulate(help, headers='firstrow',tablefmt="fancy_grid",maxcolwidths=[None, 40]))
    ########################

    ####Compression

    def compressFile(self,path,basepath, job_id):
        self.updateJob(job_id, status="(1/3) Compressing", progress="0%")
        tmp = os.path.join(self.settings.settings["temp-folder"], "Archon", basepath+".gz")


        size=os.path.getsize(path)
        with open(path, 'rb') as f:
            with open(tmp, 'wb') as f2:
                while f.tell()<size and self.jobs[job_id][-1]:
                    f2.write(gzip.compress(f.read(1024*64)))
                    self.updateJob(job_id, progress=str(int((f.tell()/size)*100))+"%")

        self.updateJob(job_id, progress="Done")

        return tmp

    def decompressFile(self,path,dest, job_id):
        self.updateJob(job_id, status="(3/3) Decompressing", progress="0%")

        size=os.path.getsize(path)
        with gzip.open(path, 'rb') as f:
            with open(dest, 'wb') as f2:
                data=f.read(1024*64)
                while data and self.jobs[job_id][-1]:
                    f2.write(data)
                    self.updateJob(job_id, progress=str(int((f.tell()/size)*100))+"%")
                    data=f.read(1024*64)


        self.updateJob(job_id, progress="Done", path=dest)

        os.remove(path)

    ########################

    ####Encryption
    def encryptFile(self, file, job_id):
        buffer_size=1024
        tmp_file = os.path.join(self.settings.settings["temp-folder"], "Archon", os.path.basename(file)+".arc")
        with open(file, "rb") as f:
            size = os.path.getsize(file)
            with open(tmp_file,"wb") as encrypted_file:
                nonce = os.urandom(12)
                data = f.read(buffer_size)
                while data and self.jobs[job_id][-1]:
                    encrypted = self.cr.encryptFileChaCha20Poly1305(data, self.master_passwd, nonce)
                    encrypted_file.write(encrypted)
                    self.updateJob(job_id, progress=str(int((f.tell()/size)*100))+"%")
                    data = f.read(buffer_size)

        if not self.jobs[job_id][-1]:
            return None,None

        self.updateJob(job_id, progress="Done")
        time.sleep(1)
        return tmp_file, nonce.hex()

    def decryptFile(self,file, nonce, job_id):

        dest = ".".join(file.split(".")[:-1])
        nonce = bytes().fromhex(nonce)
        # Encrpyt will use 1024 buffer but chacha20poly1305 will generate and a tag of size 16
        # so 1024 + 16
        size = os.path.getsize(file)
        buffer_size=1040
        with open(file, "rb") as f:
            with open(dest,"wb") as decrypted_file:
                data = f.read(buffer_size)
                while data and self.jobs[job_id][-1]:
                    decrypted = self.cr.decryptChaCha20Poly1305(data, self.master_passwd, nonce)
                    decrypted_file.write(decrypted)
                    self.updateJob(job_id, progress=str(int((f.tell()/size)*100))+"%")
                    data = f.read(buffer_size)

        if not self.jobs[job_id][-1]:
            self.updateJob(job_id, status="Canceled",progress="Terminated")
            self.jobs[job_id][-1] = "\n[-] Canceled command with id: %s"%job_id
        else:
            os.remove(file)
            self.updateJob(job_id,progress="Done")
        time.sleep(1)

        return dest



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

            _, file_size, compressed, nonce = self.cr.decryptMessage(self.getResponseFromServer(s),self.private_key).decode().split()
            #filename = bytes().fromhex(filename).decode()

            file_size = int(file_size)

            path = os.path.join(self.settings.settings["download-folder"],filename)

            if not os.path.exists(os.path.join(self.settings.settings["temp-folder"], "Archon")):
                os.mkdir(os.path.join(self.settings.settings["temp-folder"], "Archon"))

            tmp_file=os.path.join(self.settings.settings["temp-folder"], "Archon", os.path.basename(path)+".arc")

            s.send(self.cr.createMessage(b"0", self.server_public_key))


            job_id=self.getJobID()
            progress = [job_id, "DOWNLOAD","(1/%d) Downloading"%(3 if compressed=="True" else 2), "0%", path, True]
            self.jobs[job_id] = progress

            msg[0]="\n[+] Downloading %s"% filename

            with open(tmp_file,"wb") as f:
                total=0
                buffer_size = 1024*1024*8
                buffer = s.recv(buffer_size)
                while buffer and total<file_size and self.jobs[job_id][-1]:
                    total+=len(buffer)
                    f.write(buffer)
                    self.updateJob(job_id, progress=str(int((total/file_size)*100))+"%")
                    if total==file_size:
                        break
                    buffer = s.recv(buffer_size)

            if not self.jobs[job_id][-1]:
                self.updateJob(job_id, status="Canceled", progress="Terminated")
                self.jobs[job_id][-1] = "\n[-] Canceled command with id: %s"%job_id
                time.sleep(1)
                self.old_jobs.append(self.jobs.pop(job_id))
                return

            s.close()

            self.updateJob(job_id, status="(2/%d) Decrypting"%(3 if compressed=="True" else 2),progress="0%")
            tmp_file=self.decryptFile(tmp_file,nonce, job_id)

            if self.jobs[job_id][-1]:
                if compressed=="True":
                    self.updateJob(job_id, status="Decompressing",progress="0%")
                    self.decompressFile(tmp_file, path, job_id)
                else:
                    shutil.move(tmp_file, path)
            else:
                shutil.move(tmp_file, path)

            if not self.jobs[job_id][-1]: #not joined with above in case we need to compress and cancel happens there
                self.jobs[job_id][-1] = "\n[-] Unable to cancel command. Download completed"

            self.updateJob(job_id, status="Downloaded", progress="Done")
            self.old_jobs.append(self.jobs.pop(job_id))

        except Exception as e:
            self.updateJob(job_id, status="ERROR", progress="Incomplete")
            self.old_jobs.append(self.jobs.pop(job_id))
            print("Exception,",e)


    #####Upload File
    def printUploadOptionsHelp(self):
        print()
        help=[["Command","Description"]]
        help.append(("help/h/?","Print this"))
        help.append(("",""))
        help.append(("name <name>","To upload the file under different name."))
        help.append(("compress <yes/no>","To compress the file before upload (default yes)."))
        help.append(("overwrite","<yes/no>. Available if file already exists (default no)."))
        help.append(("",""))
        help.append(("show options","To print current settings for the upload."))
        help.append(("cancel","To return to the main menu."))
        help.append(("send","To send the file, begin the upload."))
        print(tabulate(help, headers='firstrow',tablefmt="fancy_grid", maxcolwidths=[None, 49]))

    def printCurrentUploadSettings(self,compress, file, name, exists, overwrite):
        print()
        help=[["Setting","Value"]]
        help.append(("Item to upload:",file))
        help.append(("Save under the name:",name))
        help.append(("Compress before upload:",str(compress)))
        if exists:
            help.append(("File already exists:\nOverwrite:","%s\n%s"%(exists,overwrite)))
        print(tabulate(help, headers='firstrow',tablefmt="fancy_grid"))

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
        os.system(self.clear)
        compress = True
        name = file
        exists = True if self.db.fileExists(os.path.basename(file)) else False
        to_overwrite=False

        print("\n[+] File '%s' has been selected to be uploaded."%file)
        print("\n[Note]: Use help for upload options")
        self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name),exists, to_overwrite)
        ans=input("\n[Upload]: %s> "%file).split()
        while True:
            if ans[0]=="name":
                _name = ' '.join(ans[1:])
                _name = self.filterFileName(_name)
                if not _name:
                    print("[!] Invalid filename. Please try again.")
                else:
                    name = _name
                    exists = True if self.db.fileExists(os.path.basename(_name)) else False
                    to_overwrite=False
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
                    self.printCurrentUploadSettings(compress, os.path.basename(file), os.path.basename(name), exists, to_overwrite)
                elif ans[0]=="overwrite":
                    if exists:
                        if not ans[1] in ("yes","no"):
                            print("[-] Invalid overwrite options\n")
                        else:
                            to_overwrite = True if ans[1]=="yes" else False
                        print("\nOverwrite -->",to_overwrite)
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

        job_id=self.getJobID()
        max=(3 if compress else 2)
        self.jobs[job_id] = [job_id, "UPLOAD","(0/%d) Uploading"%max,"0%", file_to_upload, True]

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

        if not os.path.exists(os.path.join(self.settings.settings["temp-folder"], "Archon")):
            os.mkdir(os.path.join(self.settings.settings["temp-folder"], "Archon"))

        if file_type=="FILE":
            if compress:
                #compressed_file, running
                compressed_file = self.compressFile(file_to_upload,os.path.basename(file_to_upload), job_id)

                if compressed_file:
                    size = os.path.getsize(compressed_file)

                file_to_upload = compressed_file

            self.updateJob(job_id, status="(%d/%d) Encrypting"%(max-1,max), progress="0%")
            file_to_upload, nonce = self.encryptFile(file_to_upload, job_id)


            if not file_to_upload:
                self.updateJob(job_id, status="Canceled", progress="Terminated")
                self.jobs[job_id][-1]="\n[-] Canceled command with id: %d"%job_id
                time.sleep(1)
                self.old_jobs.append(self.jobs.pop(job_id))
                return
            else:
                size = os.path.getsize(file_to_upload)


        try:

            s.send(self.cr.createMessage(("%s %s"%(str(size), nonce)).encode(),self.server_public_key))


            self.updateJob(job_id, status="(%d/%d) Uploading"%(max,max))

            wait=s.recv(1024)
            with open(file_to_upload, "rb") as f:
                buffer_size=1014*1024*2
                while f.tell()<size and self.jobs[job_id][-1]:
                    s.sendfile(f,f.tell(),buffer_size)
                    self.updateJob(job_id, progress=str(int((f.tell()/size)*100))+"%")


                if not self.jobs[job_id][-1]:
                    self.updateJob(job_id, status="Canceled", progress="Terminated")
                    self.jobs[job_id][-1] = "\n[-] Canceled command with id: %d"%job_id
                    s.close()
                else:
                    self.updateJob(job_id, status="Retrieving Files", progress="...")
                    self.getFiles()
                    time.sleep(1)
                    self.updateJob(job_id, status="Uploaded", progress="Done")

                time.sleep(1)
                self.old_jobs.append(self.jobs.pop(job_id))


        except BrokenPipeError:
            print("\n[!] Lost connection. Upload Canceled.")
            self.updateJob(job_id, status="ERROR", progress="Incomplete")
            self.old_jobs.append(self.jobs.pop(job_id))
        return

    def uploadFilePreload(self, msg):
        file_to_upload = self.getFile()
        if not file_to_upload:
            return
        options = self.getUploadFileOptions(file_to_upload)
        if not options:
            msg[0]="\n[-] Abort."
            return

        a=threading.Thread(target=self.uploadFile, args=(file_to_upload, options, msg))
        a.daemon=True
        a.start()

    ########################
    def updateJob(self, job_id, action=None, status=None, progress=None, path=None):
        items=[action, status, progress, path]
        for i in range(4):
            if items[i]:
                self.jobs[job_id][i+1] = items[i]

    def printOldJobs(self):
        if not self.old_jobs:
            print("\n[-] History is empty.")
            return
        print("\nOld records:\n")
        status=[["ID","Action","Status","Progress", "Path"]]
        for job in self.old_jobs:
            status.append(job[:-1])
        print(tabulate(status, headers="firstrow",tablefmt="fancy_grid",maxcolwidths=[None, None,None,None,25]))

    def printJobs(self):
        try:
            if not self.jobs:
                return
            status=[["ID","Action","Status","Progress", "Path"]]
            for job in self.jobs:
                status.append(self.jobs[job][:-1])
            print(tabulate(status, headers="firstrow",tablefmt="fancy_grid",maxcolwidths=[None, None,None,None,25]))
        except:return

    def printJobsLoop(self):
        try:
            while self.jobs:
                os.system(self.clear)
                self.printJobs()
                time.sleep(0.1)
        except KeyboardInterrupt:
            os.system(self.clear)
            self.printJobs()
            return
        finally:
            os.system(self.clear)
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

        self.clear = 'cls' if os.name == 'nt' else 'clear'


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
                    elif command[0]=="cancel":
                        try:
                            msg=[""]
                            to_cancel_id=int(command[1])
                            self.jobs[to_cancel_id][-1]=False
                            while self.jobs[to_cancel_id][-1]==False:
                                time.sleep(0.1)
                            print(self.jobs[to_cancel_id][-1])

                        except:
                            print("\n[!] Invalid id")
                    elif command[0]=="delete":
                        self.deleteFile(command[1])
                        self.getFiles()
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
