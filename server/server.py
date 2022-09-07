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

    def recvFile(self, client, filename, size):
        total=0
        with open(filename, "wb") as f:
            buffer = client.recv(1024*1024)
            while True:
                f.write(buffer)
                total+=len(buffer)
                if not buffer:
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
        #first command must be EXCHANGE for first contact or 'EXCHANGE 0' for later contact
        first_command = client.recv(1024*10).decode().split(maxsplit=1)

        if not first_command[0]=="EXCHANGE":# in (b"EXCHANGE", b"PASS"):
            client.close()
            return

        #################################
        ##EXCHANGE KEYS WITH CLIENT
        self.sendMessage(client, self.public_pem)
        client_public_key = self.cr.getPublicFromPEM(self.cr.decryptMessage(client.recv(1024*1024),self.private_key))
        #################################

        if len(first_command)==1: # first contact
            uuid_ = str(uuid.uuid4())
            self.sendMessage(client, ("Hallo from Server %s"%uuid_).encode(),client_public_key)

        else:
            client.send(self.cr.createMessage(b"0", client_public_key))
        ##########################################
            data = self.cr.decryptMessage(client.recv(1024), self.private_key).decode().split()
            command_uuid = data[0]
            username = data[1]
            command = data[2:]

            userID = self.H.getUserID(username)

            user_uuid = self.H.getUUID(username)


            if user_uuid==command_uuid:
                client.send(self.cr.createMessage(b"0", client_public_key))
            else:
                client.send(self.cr.createMessage(b"1", client_public_key))
                client.close()
                return


            self.executeCommand(userID, command_uuid,client, client_public_key, command)
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
        # IF USER WANTS TO LIST HIS FILES, THIS ACTION WILL TAKE PLACE HERE ON THIS THREAD
        masterPassword,userID = self.H.getMasterPassword(username, password)

        self.H.addUUID(username, uuid_)
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

                else:
                    client.close()
                    return
            except ConnectionResetError:
                client.close()
                return

    def executeCommand(self,userID, command_uuid, client, client_public_key, command):
        cpath = os.path.join("database","FILES",userID)

        #needs check on index
        if command[0] == "DOWNLOAD":
            item_to_download = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))

            self.H.addLockedFile(item_to_download)

            ###########
            n=os.path.join("database/METADATA",userID,os.path.basename(item_to_download)+".txt")
            with open(n,"r") as f:
                f=f.readlines()

                compress, nonce = f[4:]

                self.sendFile(client, item_to_download, compress, nonce, client_public_key)

            with open(n,"w") as f2:
                f[2]=str(datetime.datetime.now()).split(".")[0]+"\n"
                f=''.join(f)
                f2.write(f)

            self.H.removeLockedFile(item_to_download)

        elif command[0]=="UPLOAD":
            #size = command[3]
            type = command[2]
            compress = command[3]
            filename = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))

            #client.send(self.cr.createMessage(b"0", client_public_key))

            size, nonce = self.cr.decryptMessage(client.recv(1024*10), self.private_key).decode().split()
            size=int(size)

            client.send(self.cr.createMessage(b"0", client_public_key))
            if type=="FILE":
                res = self.recvFile(client, filename, int(size))
                if not res:
                    return
                with open(os.path.join("database/METADATA",userID,os.path.basename(filename)+".txt"),"w") as f:
                    p = Path(filename).stat()
                    modification_date = datetime.datetime.fromtimestamp(int(p.st_mtime))
                    creation_date = datetime.datetime.fromtimestamp(int(p.st_ctime))
                    f.write("%s\n%s\n%s\n%s\n%s\n%s"%(type, size, str(modification_date), str(creation_date),compress,nonce))
                client.send(self.cr.createMessage(b'0',client_public_key))

        elif command[0]=="DELETE":
                filename = os.path.abspath(os.path.join(cpath, bytes().fromhex(command[1]).decode()))
                basepath=os.path.join("database/FILES",userID)
                path=os.path.join("database/FILES",userID, filename)
                if not basepath in path:
                    client.send(self.cr.createMessage(b"1Action reported", client_public_key))
                    print("[!] Action to exploit delete command to delete below users path")
                elif not os.path.exists(filename):
                    client.send(self.cr.createMessage(b"1", client_public_key))
                else:
                    client.send(self.cr.createMessage(b"0", client_public_key))

                client.close()

                os.remove(path)
                os.remove(os.path.join("database/METADATA",userID,os.path.basename(filename)+".txt"))


        else:
            print("unknown")

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
