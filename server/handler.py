import os
import shutil
import uuid

from argon2 import hash_password_raw

from database import DataBase
from Cryptography import Cryptography


class Handler:
    def __init__(self):
        self.db = DataBase("database.db")
        self.cr = Cryptography()
        #self.purgeDatabases()
    def purgeDatabase(self):
        if os.path.exists(os.path.join("database","DATA")):
            shutil.rmtree(os.path.join("database","DATA"))
            os.mkdir(os.path.join("database","DATA"))
        if os.path.exists(os.path.join("database","FILES")):
            shutil.rmtree(os.path.join("database","FILES"))
            os.mkdir(os.path.join("database","FILES"))

    def createUserFolder(self):
        user_id = uuid.uuid4().hex
        path = os.path.join("database","DATA",user_id)
        while os.path.exists(path):
            user_id = uuid_uuid4().hex
            path = os.path.join("database","DATA",user_id)
        os.mkdir(path)
        os.mkdir(os.path.join("database","FILES",user_id))
        os.mkdir(os.path.join("database","METADATA",user_id))
        return user_id

    def changePassword(self,name,password,new_password):
        user_settings = self.db.getUserSettings(name)
        new_hash = self.cr.createHash(new_password)
        new_user_id = self.createUserFolder()
        settings = (name, new_hash, new_user_id)

        master_passwd = self.getMasterPassword(name,password)
        with open(os.path.join("database","DATA",new_user_id,"salt"),"wb") as salt_file, open(os.path.join("database","DATA",new_user_id,"master_passwd"),"wb") as master_passwd_file, open(os.path.join("database","DATA",new_user_id,"iv_file"),"wb") as iv_file, open(os.path.join("database","DATA",new_user_id,"tag"),"wb") as tag_file:
            salt = os.urandom(16)
            iv = os.urandom(16)
            hash = hash_password_raw(hash_len=16, password=new_password.encode(), salt=salt).hex()

            encrypted_master_passwd, tag = self.cr.encryptAES_GCM(hash, iv, master_passwd)

            salt_file.write(salt)
            iv_file.write(iv)
            master_passwd_file.write(encrypted_master_passwd)
            tag_file.write(tag)

        self.db.passwordResetProtocol(name,new_hash,new_user_id)
        shutil.rmtree(os.path.join("database","DATA",user_settings[2]))

    def createUser(self, name,password):
        if self.db.userExists(name): return False

        hash = self.cr.createHash(password)

        user_id = self.createUserFolder()

        settings = (name, hash, user_id,0,0,0,0)

        with open(os.path.join("database","DATA",user_id,"salt"),"wb") as salt_file, open(os.path.join("database","DATA",user_id,"master_passwd"),"wb") as master_passwd_file, open(os.path.join("database","DATA",user_id,"iv_file"),"wb") as iv_file, open(os.path.join("database","DATA",user_id,"tag"),"wb") as tag_file:
            salt = os.urandom(16)
            iv = os.urandom(16)
            hash = hash_password_raw(hash_len=16, password=password.encode(), salt=salt).hex()
            master_passwd = os.urandom(32)

            encrypted_master_passwd, tag = self.cr.encryptAES_GCM(hash, iv, master_passwd)

            salt_file.write(salt)
            iv_file.write(iv)
            master_passwd_file.write(encrypted_master_passwd)
            tag_file.write(tag)

        self.db.addUserToDatabase(settings)
        """
        print("\nNEW USER (%s,%s)"%(name,password))
        print("HASH: %s", hash)
        print("USER_ID:", user_id)
        print("\nSettings for Master Password:\n")
        print("SALT:",salt)
        print("IV:",iv)
        print("ENCRYPTED MASTER PASSWORD:",encrypted_master_passwd)
        print("MASTER PASSWORD:",master_passwd)
        """
        return True

    def authenticate(self,name,password):
        return self.cr.validateHash(name,password)

    def deleteUser(self,name,password):
        authenticated = self.authenticate(name,password)
        if not authenticated: return False
        self.db.deleteUser(name)

    def getMasterPassword(self, name,password):
        data = self.db.getUserSettings(name)
        if not data:return None,None
        authenticated = self.authenticate(data[1],password)
        if not authenticated: return None,None
        user_id = data[2]
        with open(os.path.join("database","DATA",user_id,"salt"),"rb") as salt_file, open(os.path.join("database","DATA",user_id,"master_passwd"),"rb") as master_passwd_file, open(os.path.join("database","DATA",user_id,"iv_file"),"rb") as iv_file, open(os.path.join("database","DATA",user_id,"tag"),"rb") as tag_file:
            salt, iv,master_passwd, tag = salt_file.read(), iv_file.read(), master_passwd_file.read(), tag_file.read()

            hash = hash_password_raw(hash_len=16, password=password.encode(), salt=salt).hex()

            master = self.cr.decryptAES_GCM(hash,iv,tag,master_passwd)

            return master,data[2]
    def printDatabase(self):
        self.db.printDatabase()
