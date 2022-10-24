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
        if os.path.exists(os.path.join("database","FILES")):
            shutil.rmtree(os.path.join("database","FILES"))
            os.mkdir(os.path.join("database","FILES"))

    def createUserFolder(self):
        user_id = uuid.uuid4().hex
        while self.db.userExistsWithID(user_id)[0]!=0:
            user_id = uuid.uuid4().hex
        os.mkdir(os.path.join("database","FILES",user_id))
        return user_id

    def changePassword(self,name,password,new_password):
        user_settings = self.db.getUserSettings(name)
        new_hash = self.cr.createHash(new_password)
        new_user_id = self.createUserFolder()

        master_passwd, _ = self.getMasterPassword(name,password)
        salt = os.urandom(16)
        iv = os.urandom(16)
        hashed = hash_password_raw(hash_len=16, password=new_password.encode(), salt=salt).hex()

        encrypted_master_passwd, tag = self.cr.encryptAES_GCM(hashed, iv, master_passwd)


        settings = (new_hash, new_user_id, salt, encrypted_master_passwd, iv, tag)

        self.db.passwordResetProtocol(name,settings)

    def userExists(self, user):
        return self.db.userExists(user)

    def getUserSettings(self, user):
        return self.db.getUserSettings(user)

    def updateUserPassword(self, user_id, info):
        return self.db.passwordResetProtocol(user_id, info)

    def createUser(self, name,password, info):
        if self.db.userExists(name): return False

        user_id = self.createUserFolder()

        info.insert(1, user_id)
        info.insert(0, name)

        self.db.addUserToDatabase(info)
        return user_id

    def authenticate(self,name,password):
        return self.cr.validateHash(name,password)

    def deleteUser(self,name,password):
        authenticated = self.authenticate(name,password)
        if not authenticated: return False
        self.db.deleteUser(name)


    def getUserID(self, name):
        return self.db.getUserSettings(name)[2]

    def getMasterPassword(self, name,password):
        data = self.db.getUserSettings(name)
        if not data:return None,None
        authenticated = self.authenticate(data[1],password)
        if not authenticated: return None,None

        salt, master_passwd, iv, tag = data[3:]

        return salt+master_passwd+iv+tag,data[2]

    def printDatabase(self):
        self.db.printDatabase()

    def printCommands(self):
        self.db.printCommands()

    def printLockedFiles(self):
        self.db.printLockedFiles()

    def addLockedFile(self, file):
        self.db.addLockedFile(file)

    def removeLockedFile(self, file):
        self.db.removeLockedFile(file)

    def addUUID(self, username, user_uuid):
        self.db.addUUID(username, user_uuid)

    def getUUID(self, username):
        return self.db.getUUID(username)

    def addFileToDB(self, userID, parent, file, metadata):
        self.db.addFileToDB(userID, parent, file, metadata)

    def deleteFile(self, userID, parent, filename):
        self.db.deleteFile(userID, parent, filename)

    def getFilesFromUser(self, userID, parent):
        return self.db.getFilesFromUser(userID, parent)

    def getUserFile(self, userID, parent, filename):
        return self.db.getUserFile(userID, parent, filename)

    def updateModDate(self, userID, parent, filename, mod_date):
        return self.db.updateModDate(userID, parent, filename, mod_date)
