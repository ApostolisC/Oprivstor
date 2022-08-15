import os
import sys
import shutil
import uuid
import datetime

from pathlib import Path

import socket
import threading
import time

from Cryptography import Cryptography

from database import DataBase

from handler import Handler

"""
#FORMAT OF self.users:
#            {'user-id': {'active': blool, 'active-connections': int, 'commands': int ,'running-commands': int , 'master_passwd': str, , 'locked-files':[], 'uuid':'command', 'uuid': 'command2'},
#             'user-id2': {'active': bool, 'active-connections': int, 'running-commands': int, 'master_passwd': str, 'uuid':'commandX', 'uuid': 'commandY'} }
"""

class Server:
    window=None

    def purgeDatabase(self):
        if not self.H:
            print("No handler fount!")
            return
        self.H.purgeDatabase()
    def printDB(self):
        self.H.printDatabase()

    def sendMessage(self, client, message, client_public_key=None):
        if client_public_key:
            message = self.cr.createMessage(message,client_public_key)
            size_int=len(message)
            size = self.cr.createMessage(str(size_int).encode(), client_public_key)
        else:
            size = str(len(message)).encode()
            size_int=len(message)
        client.send(size.hex().encode())
        wait = client.recv(1024)

        total=0
        while total<size_int:
            buffer = message[total:]
            client.send(buffer)
            total+=len(buffer)

    def recvFile(self, client, filename, client_public_key, user_settings, userID, command_uuid, size, from_folder=False):
        total=0
        print("Expected of size:",size)
        with open(filename, "wb") as f:
            buffer = client.recv(1024*1024)
            while True:
                f.write(buffer)
                total+=len(buffer)
                if not buffer or total==size:
                    break
                buffer=client.recv(1024*1024)
        if total<size:
            os.remove(filename)
            return False
        else:
            return True

    def sendFile(self, client, filename, compress, nonce, client_public_key):
        with open(filename, "rb") as f:
            try:
                size = os.path.getsize(filename)
                filename = os.path.basename(filename).encode().hex()
                self.sendMessage(client,("%s %s %s %s"%(filename, str(size), compress, nonce)).encode(), client_public_key)

                wait = client.recv(1024)

                client.sendfile(f)

            except Exception as e:
                print(e)
                return

    def client_response(self,client):
        first_command = client.recv(1024*10).split(maxsplit=1)
        #It can be EXCHANGE or EXECUTE
        if not first_command[0] in (b"EXCHANGE", b"PASS"):
            client.close()
            return

        if first_command[0]==b"EXCHANGE":
            self.sendMessage(client, self.public_pem)
            r = client.recv(1024*1024)
            client_public_key = self.cr.getPublicFromPEM(self.cr.decryptMessage(r,self.private_key))
            self.sendMessage(client, b"Hallo from Server ",client_public_key)
        else:
            command = self.cr.decryptMessage(first_command[1], self.private_key).decode().split()
            userID = DataBase("database.db").getUserID(command[0])
            command_uuid = command[1]
            self.executeCommand(userID, command_uuid,client)
            return

        self.H = Handler()
        #Authentication loop
        while True:
            try:
                enc_response = client.recv(1024*1024)
            except ConnectionResetError:
                client.close()
                return
            if not enc_response:
                client.close()
                return
            command = self.cr.decryptMessage(enc_response,self.private_key).decode().split() #this command must me either login or Signup

            action = bytes.fromhex(command[0]).decode()
            if action not in ("LOGIN", "SIGNUP") or len(command)!=3:
                self.sendMessage(client, b" Invalid Command. Action reported!",client_public_key)
                client.close()
                return
            username = bytes.fromhex(command[1]).decode()
            password = bytes.fromhex(command[2]).decode()
            if not username:
                self.sendMessage(client, b"1Username must not be null.", client_public_key)
                continue
            if " " in username:
                self.sendMessage(client, b"1Username must not contain spaces.", client_public_key)
                continue


            if action=="SIGNUP":
                if len(password) < 8:
                    self.sendMessage(client,b"1Password must be at least of length 8!", client_public_key)
                    continue
                elif len(password) >255:
                    self.sendMessage(client,b"1Password is too big! Maximum length: 255.", client_public_key)
                    continue
                result = self.H.createUser(username,password)
                masterPassword,userID = self.H.getMasterPassword(username, password)
                if not result:
                    self.sendMessage(client, b"1User already exists!", client_public_key)
                else:
                    self.sendMessage(client,b"0[Server]: Account created! Welcome %b."%username.encode(),client_public_key)
                    wait = client.recv(1024)
                    self.sendMessage(client, masterPassword, client_public_key)
                    break
            else:
                masterPassword,userID = self.H.getMasterPassword(username, password)
                if (masterPassword,userID)==(None,None):
                    self.sendMessage(client,b"1Wrong Username or Password. Please Try Again.", client_public_key)

                else:
                    self.sendMessage(client,b"0[Server]: Welcome %b!"%username.encode(),client_public_key)
                    wait = client.recv(1024)
                    self.sendMessage(client, masterPassword, client_public_key)
                    break

        #If user managed to log into his account, the loop will break knowing we can execute commands
        # IF USER WANTS TO LIST HIS FILES, THIS ACTION WILL TAKE PLACE HERE.
        # FOR EVERY OTHER ACTION (EG DOWNLOAD, UPLOAD) WE WILL CREATE A UUID AND SAVE THE UUID WITH THE COMMAND ON A DICTIONARY
        # THIS IS BC WE DONT WANT TO BLOCK OTHER ACTIONS. USER MAY WANT TO LIST OTHER FILES WHILE DOWNLOADING.
        # SO WE CANT MESS WITH THE DOWNLOAD STREAM SENDING DATA
        masterPassword,userID = self.H.getMasterPassword(username, password)
        self.users[userID] = {'active':True, "active-connections": 1,"commands":0, "running-commands":0, "master_passwd": masterPassword, "locked-files":[], "client-public-key":client_public_key}
        cpath = os.path.join("database","FILES",userID)
        while True:
            try:
                command = client.recv(1024*1024)
                if not command:
                    client.close()
                    return
                command=self.cr.decryptMessage(command,self.private_key).decode().split()
                if command[0]=="LS" and len(command)<=2:
                    command[1] = bytes().fromhex(command[1]).decode()

                    path = os.path.abspath(os.path.join(cpath,command[1]))
                    if not os.path.exists(path):
                        self.sendMessage(client, b"", client_public_key)
                        continue

                    if not  os.path.abspath(os.path.join("database","FILES",userID)) in path:
                        self.sendMessage(client, b"",client_public_key)
                        continue
                    cpath = path

                    if os.path.isfile(cpath):
                        self.sendMessage(client, b"", client_public_key)
                        continue
                    obj = os.scandir(cpath)

                    buffer=b""
                    for entry in obj :
                        path =  os.path.join(cpath,entry.name)
                        _path = os.path.join("database","METADATA",userID,os.path.basename(path))+".txt"
                        if not os.path.exists(_path):
                            continue
                        else:
                            with open(_path,"rb") as f:
                                info = f.readlines()

                                file_type, size, modification_date, creation_date, compressed, _ = [v.hex() for v in info]


                        buffer+=("%s %s %s %s %s %s "%(entry.name.encode().hex(), file_type, size,modification_date, creation_date, compressed)).encode()
                        if len(buffer) > 200*1024:
                            self.sendMessage(client,buffer, client_public_key)
                            buffer=b""
                    self.sendMessage(client, buffer, client_public_key) if buffer else self.sendMessage(client, b"", client_public_key)
                elif command[0] == "DOWNLOAD":
                    item_to_download = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))
                    if item_to_download in self.users[userID]["locked-files"]:
                        self.sendMessage(client,b"!File '%s' is locked because another action is performed on it.\nYou can cancel that action and try again."%item_to_download.encode(), client_public_key)
                        continue

                    command_uuid = str(uuid.uuid4())
                    self.users[userID][command_uuid] = ' '.join(command)
                    self.users[userID]["commands"] +=1
                    self.sendMessage(client,command_uuid.encode(), client_public_key)
                    continue

                elif command[0] == "UPLOAD":
                    item_to_upload = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))
                    if item_to_upload in self.users[userID]["locked-files"]:
                        self.sendMessage(client,b"!File is locked because another action is performed on it.\nYou can cancel that action and try again.", client_public_key)
                        continue
                    command_uuid = str(uuid.uuid4())
                    self.users[userID][command_uuid] = ' '.join(command)
                    self.users[userID]["commands"] +=1
                    self.sendMessage(client,command_uuid.encode(), client_public_key)
                    continue
                else:
                    client.close()
                    return
            except ConnectionResetError:
                client.close()
                return

    def executeCommand(self,userID, command_uuid, client):
        cpath = os.path.join("database","FILES",userID)
        user_settings = self.users[userID]
        command = user_settings[command_uuid].split()
        master_passwd = user_settings["master_passwd"]
        user_settings['active-connections'] +=1
        user_settings['running-commands'] +=1
        client_public_key = self.users[userID]['client-public-key']
        #private_key = self.users[userID]['server-private-key']
        if command[0] == "DOWNLOAD":
            item_to_download = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))
            user_settings["locked-files"].append(item_to_download)
            ###########
            n=os.path.join("database/METADATA",userID,item_to_download.split("/")[-1]+".txt")
            with open(n,"r") as f:
                f=f.readlines()

                compress, nonce = f[4:]

                self.sendFile(client, item_to_download, compress, nonce, client_public_key)

            with open(n,"w") as f2:
                f[2]=str(datetime.datetime.now()).split(".")[0]+"\n"
                f=''.join(f)
                f2.write(f)


            user_settings['active-connections'] -=1
            user_settings['running-commands'] -=1
            user_settings['locked-files'].remove(item_to_download)
            self.users[userID]["commands"] -=1
            user_settings.pop(command_uuid)

        elif command[0]=="UPLOAD":
            size = command[2]
            type = command[3]
            compress = command[4]
            nonce = command[5]
            print("nonce:",nonce)
            filename = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))

            user_settings["locked-files"].append(filename)
            if os.path.exists(filename):
                client.send(self.cr.createMessage(b"1", client_public_key))
            else:
                client.send(self.cr.createMessage(b"0", client_public_key))
            verification = self.cr.decryptMessage(client.recv(1024*10), self.private_key).decode()
            if verification=="1":
                user_settings['active-connections'] -=1
                user_settings['running-commands'] -=1
                user_settings['locked-files'].remove(filename)
                self.users[userID]["commands"] -=1
                user_settings.pop(command_uuid)
                return
            if type=="FILE":
                res = self.recvFile(client, filename, client_public_key, user_settings, userID, command_uuid, int(size))
                if not res:
                    print("not res")
                    return
                client.send(self.cr.createMessage(b'0',client_public_key))
                with open(os.path.join("database/METADATA",userID,filename.split("/")[-1]+".txt"),"w") as f:
                    p = Path(filename).stat()
                    modification_date = datetime.datetime.fromtimestamp(int(p.st_mtime))
                    creation_date = datetime.datetime.fromtimestamp(int(p.st_ctime))
                    f.write("%s\n%s\n%s\n%s\n%s\n%s"%(type, size, str(modification_date), str(creation_date),compress,nonce))
            else:
                filename=filename+".zip"
                self.recvFile(client, filename, client_public_key, user_settings, userID, command_uuid, int(size),True)
                with ZipFile(filename, 'r') as zip_ref:
                    zip_ref.extractall(cpath)
            user_settings['active-connections'] -=1
            user_settings['running-commands'] -=1
            user_settings['locked-files'].remove(filename)
            self.users[userID]["commands"] -=1
            user_settings.pop(command_uuid)

    def Initialize(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host,int(port)))

        s.listen(100)
        print("Server up and running at %s:%s"%(host,port))
        while True:
            client,addr = s.accept()
            print("new connection",addr)
            a = threading.Thread(target = self.client_response, args=(client,))
            a.daemon=True
            a.start()

    def __init__(self,host,port):
        self.H = Handler()
        self.users = {}
        self.cr = Cryptography()
        self.private_key,self.public_key, self.public_pem = self.cr.createRSAKeysWithPem()

        self.Initialize(host,port)

if len(sys.argv[1:])==2:
    host, port = sys.argv[1:]
    Server(host, port)

elif len(sys.argv)==2:
    if sys.argv[1]=="--help":
        print("Archon\n\nUsage: python3 %s <address> <port>\n"%sys.argv[0])
    else:
        print("Invalid options. Please use --help option.")
else:
    print("Invalid options. Please use --help option.")
