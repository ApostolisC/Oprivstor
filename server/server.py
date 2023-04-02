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
from personalDatabase import personalDatabase

from handler import Handler

"""
* encrypt personal database
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

    def recvFile(self, client, filename, size):
        total=0
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
        #first command must be EXCHANGE for first contact or 'EXCHANGE 0' for later contact
        first_command = client.recv(1024*10).decode().split(maxsplit=1)

        if not first_command:
            client.close()
            return

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
                if command[0] not in ("MKDIR", "DELETE", "RENAME"):
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
                elif len(username) > 32:
                    self.sendMessage(client,b"1Username is too big! Maximum length: 32.", client_public_key)
                    continue
                if self.H.userExists(username):
                    self.sendMessage(client, b"1User already exists!", client_public_key)
                else:
                    self.sendMessage(client, b"0",client_public_key)
                    enc_info = self.cr.decryptMessage(client.recv(1024), self.private_key).decode()

                    #salt = enc_info[0:16]
                    #encrypted_master_passwd = enc_info[16:48]
                    #iv = enc_info[48:64]
                    #tag = enc_info[64:80]
                    #hash = enc_info[80:]
                    salt, encrypted_master_passwd, iv, tag, hash = [bytes.fromhex(v) for v in enc_info.splitlines()]
                    info = [hash, salt,encrypted_master_passwd,iv,tag]
                    userID = self.H.createUser(username,password, info)
                    self.sendMessage(client, b"0",client_public_key)

                    break
            else:
                enc_info ,userID = self.H.getMasterPassword(username, password)
                if (enc_info,userID)==(None,None):
                    self.sendMessage(client,b"1Wrong Username or Password. Please Try Again.", client_public_key)

                else:
                    self.sendMessage(client,b"0[Server]: Welcome %b!"%username.encode(),client_public_key)
                    wait = client.recv(1024)
                    self.sendMessage(client, enc_info, client_public_key)
                    break

        #If user managed to log into his account, the loop will break knowing we can execute commands
        # IF USER WANTS TO LIST HIS FILES, THIS ACTION WILL TAKE PLACE HERE ON THIS THREAD
        userID = self.H.getUserSettings(username)[2]

        personal_database = personalDatabase(os.path.join("database","databases",userID+".db"))

        self.H.addUUID(username, uuid_)
        while True:
            cpath = os.path.join("database","FILES",userID)
            try:
                command = client.recv(1024*1024)
                if not command:
                    client.close()
                    return
                command=self.cr.decryptMessage(command,self.private_key).decode().split()

                if len(command)!=2 or command[0]!="LS":
                    self.sendMessage(client, b"1Invalid command", client_public_key)
                    client.close()
                    return

                path = bytes().fromhex(command[1]).decode()

                files = personal_database.getFiles(path)

                if not files:
                    self.sendMessage(client, b"", client_public_key)
                else:
                    buffer=b""
                    for file in files:
                        metadata=[str(v) for v in file[2:-1]]
                        filename, file_type, size, modification_date, upload_date, compressed = [v.encode().hex() for v in metadata]


                        buffer+=("%s %s %s %s %s %s "%(filename, file_type, size,modification_date, upload_date, compressed)).encode()
                        if len(buffer) > 200*1024:
                            self.sendMessage(client,buffer, client_public_key)
                            buffer=b""
                    self.sendMessage(client, buffer, client_public_key) if buffer else self.sendMessage(client, b"", client_public_key)

            except ConnectionResetError:
                client.close()
                return

    def executeCommand(self,userID, command_uuid, client, client_public_key, command):
        personal_database = personalDatabase(os.path.join("database","databases",userID+".db"))
        cpath = os.path.join("database","FILES",userID)

        #needs check on index
        if command[0] == "DOWNLOAD":
            item_to_download = bytes().fromhex(command[1]).decode()
            basename = os.path.basename(item_to_download)
            dirname = os.path.dirname(item_to_download)

            path_to_file = personal_database.getFile(dirname, basename)
            if not path_to_file:
                self.sendMessage(client, b"1Invalid Path!", client_public_key)
                client.close()
                return
            if path_to_file[3]=="DIR":
                self.sendMessage(client, b"1Item is not a file", client_public_key)
                client.close()
                return

            self.H.addLockedFile(item_to_download)

            ###########
            #file_info = self.H.getUserFile(userID, "/" if dirname==userID else dirname, os.path.basename(item_to_download))[0]
            compress, nonce = path_to_file[7:]

            self.sendFile(client, os.path.join("database","FILES", userID, path_to_file[0]), compress, nonce, client_public_key)

            personal_database.updateModDate(dirname, os.path.basename(item_to_download), str(datetime.datetime.now()).split(".")[0])

            self.H.removeLockedFile(item_to_download)

        elif command[0]=="UPLOAD":
            #size = command[3]
            type = command[2]
            compress = command[3]

            filename = bytes().fromhex(command[1]).decode()
            basename = os.path.basename(filename)
            dirname = os.path.dirname(filename)

            file_id = str(uuid.uuid4())

            path_to_write = os.path.abspath(os.path.join("database","FILES",userID, file_id))


            if dirname!="/":
                parent = personal_database.getFile(os.path.dirname(dirname), os.path.basename(dirname))
                if not parent:
                    client.send(self.cr.createMessage(b"1Invalid Path", client_public_key))
                    client.close()
                    return
                else:
                    if parent[3]!="DIR":
                        client.send(self.cr.createMessage(b"1Parent not a directory", client_public_key))
                        client.close()
                        return


            size, nonce = self.cr.decryptMessage(client.recv(1024*10), self.private_key).decode().split()
            size=int(size)

            client.send(self.cr.createMessage(b"0", client_public_key))
            if type=="FILE":
                res = self.recvFile(client, path_to_write, int(size))
                if not res:
                    return


                p = Path(path_to_write).stat()
                modification_date = str(datetime.datetime.fromtimestamp(int(p.st_mtime)))
                creation_date = str(datetime.datetime.fromtimestamp(int(p.st_ctime)))

                metadata = [type, size, modification_date, creation_date, compress, nonce]

                personal_database.addFileToDB(file_id, dirname, basename, metadata)

                client.send(self.cr.createMessage(("\n".join([basename,type, str(size), modification_date, creation_date, compress])).encode(), client_public_key))

        elif command[0]=="MKDIR":
            dir_=bytes().fromhex(command[1]).decode()
            basename = os.path.basename(dir_)
            dirname = os.path.dirname(dir_)

            if dirname!="/":
                if not personal_database.getFile(os.path.dirname(dirname), os.path.basename(dirname)):
                    client.send(self.cr.createMessage(b"1Invalid Path.", client_public_key))
                    client.close()
                    return

            if personal_database.getFile(dirname, basename):
                client.send(self.cr.createMessage(b"1Path Already Exists", client_public_key))
                client.close()
                return

            folder_id = str(uuid.uuid4())

            try:
                modification_date = datetime.datetime.fromtimestamp(int(time.time()))
                upload_date = datetime.datetime.fromtimestamp(int(time.time()))

                metadata = ["DIR", "-", str(modification_date), str(upload_date), "-", "-"]

                personal_database.addFileToDB(folder_id, dirname, basename, metadata)

                client.send(self.cr.createMessage(("\n".join(metadata[:-1])).encode(), client_public_key))

            except Exception as e:
                print(e)
                client.send(self.cr.createMessage(b"1Action Failed", client_public_key))

        elif command[0]=="CHPASSWD":
            enc_info="\n".join(command[1:])

            salt, encrypted_master_passwd, iv, tag, hash = enc_info.splitlines()


            info = [hash, salt, encrypted_master_passwd,iv,tag]
            info = [bytes().fromhex(v) for v in info]
            result = self.H.updateUserPassword(userID, info)
            if result:
                client.send(self.cr.createMessage(b"0",client_public_key))
            else:
                client.send(self.cr.createMessage(b"1Failed to Change Password",client_public_key))

        elif command[0]=="MOVE":
            item = bytes().fromhex(command[1]).decode()
            destination = bytes().fromhex(command[2]).decode()

            if not personal_database.getFile(os.path.dirname(item),os.path.basename(item)):
                client.send(self.cr.createMessage(b"1File or Folder doesn't exist",client_public_key))
                client.close()
                return

            if destination!="/":
                if not personal_database.getFile(os.path.dirname(destination), os.path.basename(destination)):
                    client.send(self.cr.createMessage(b"1Destination doesn't exist.",client_public_key))
                    client.close()
                    return

            personal_database.changeParent(item, destination)



        elif command[0]=="DELETE":
            #TO REMOVE FROM DATABASE
            file_to_delete = bytes().fromhex(command[1]).decode()
            basename = os.path.basename(file_to_delete)
            dirname = os.path.dirname(file_to_delete)

            file_info = personal_database.getFile(dirname, basename)

            if not file_info:
                client.send(self.cr.createMessage(b"1Item doesn't exist.", client_public_key))

            else:
                self.deletePath(file_to_delete, personal_database, userID)

                client.send(self.cr.createMessage(b"0", client_public_key))

            client.close()

        elif command[0]=="RENAME":
            full_path = bytes().fromhex(command[1]).decode()
            new_name = bytes().fromhex(command[2]).decode()

            dirname = os.path.dirname(full_path)
            basename = os.path.basename(full_path)

            ans=""

            if len(new_name)>256:
                ans = "1File or Folder name must be less than 256 characters!"
            elif personal_database.getFile(dirname, new_name):
                ans="1File or Folder already exists under that name."
            elif not personal_database.getFile(dirname, basename):
                ans="1File or Folder doesn't exist."
            else:
                ans="0"


            client.send(self.cr.createMessage(ans.encode(), client_public_key))
            client.close()


            personal_database.renameItem(dirname, basename, new_name)



        else:
            client.close()
            return

    def deletePath(self, parent, database, userID):
        for item in database.getFiles(parent):
            if item[3]!="DIR":
                location = os.path.join("database","FILES", userID, item[0])
                os.remove(location)
            else:
                self.deletePath(os.path.join(parent,item[2]), database, userID)
            database.deleteFile(parent, item[2])
        database.deleteFile(os.path.dirname(parent), os.path.basename(parent))

    def Initialize(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host,int(port)))

        s.listen(100)
        print("\n[+] Server up and running at %s:%s"%(host,port))
        while True:
            client,addr = s.accept()
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
        print("Oprivstor\n\nUsage: python3 %s <address> <port>\n"%sys.argv[0])
    else:
        print("Invalid options. Please use --help option.")
else:
    print("Invalid options. Please use --help option.")
