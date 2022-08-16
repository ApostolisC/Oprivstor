import os
import sqlite3
from tabulate import tabulate

class DataBase:

    def __init__(self,database):
        if not os.path.exists("database"):
            os.mkdir("database")
            os.mkdir(os.path.join("database","FILES"))
            os.mkdir(os.path.join("database","DATA"))
            os.mkdir(os.path.join("database","METADATA"))


        database_exists=os.path.exists("database.db")

        self.sqliteConnection = sqlite3.connect(database, check_same_thread=False)

        self.cursor = self.sqliteConnection.cursor()

        if not database_exists:
            self.createDatabase()

    def getRecords(self):
        return self.cursor.execute("SELECT * FROM USERS").fetchall()

    def userExists(self, user):
        return self.cursor.execute("SELECT * FROM USERS WHERE Name=?",(user,)).fetchall()
        #self.sqliteConnection.commit()

    def getUserSettings(self,user):
        try:
            return self.cursor.execute("SELECT * FROM USERS WHERE Name=?",(user,)).fetchall()[0]

        except IndexError:
            return None

    def getUserID(self,user):
        try:
            return self.cursor.execute("SELECT * FROM USERS WHERE Name=?",(user,)).fetchall()[0][2]
        except IndexError:
            return None

    def deleteUser(self,name):
        self.cursor.execute("DELETE FROM USERS WHERE Name=?",(name,))
        self.sqliteConnection.commit()

    def addLockedFile(self, file):
        self.cursor.execute("INSERT INTO LOCKED_FILES VALUES (?);",(file,))
        self.sqliteConnection.commit()

    def removeLockedFile(self,file):
        self.cursor.execute("DELETE FROM LOCKED_FILES WHERE FILE=?",(file,))
        self.sqliteConnection.commit()

    def printDatabase(self):
        users = self.cursor.execute("SELECT * FROM USERS").fetchall()
        users.insert(0,["Username","Hash","User ID"])
        print(tabulate(users, headers='firstrow'))
        print()

    def printLockedFiles(self):
        files = self.cursor.execute("SELECT * FROM LOCKED_FILES").fetchall()
        files.insert(0,["File"])
        print(tabulate(files, headers='firstrow'))
        print()

    def printCommands(self):
        commands = self.cursor.execute("SELECT * FROM LOCKED_FILES").fetchall()
        commands.insert(0,["Name", "PUBLIC_KEY"])
        print(tabulate(commands, headers='firstrow'))
        print()

    def addUserToDatabase(self, s):
        self.cursor.execute("INSERT INTO USERS VALUES (?,?,?);",(s[0],s[1],s[2],))
        self.cursor.execute("INSERT INTO SESSIONS VALUES (?,null);",(s[0],))
        self.sqliteConnection.commit()

    def addUUID(self, username, uuid_):
        self.cursor.execute("""
        UPDATE SESSIONS

        SET UUID = ?

        WHERE USERNAME = ?;

        """,(uuid_,username,))
        self.sqliteConnection.commit()

    def getUUID(self, username):
        result = self.cursor.execute("SELECT UUID FROM SESSIONS WHERE USERNAME = (?);",(username, )).fetchall()
        return result[0][0]

    def createDatabase(self):
        query = """CREATE TABLE USERS (

                    Name VARCHAR(255),

                    Hash VARCHAR(255),

                    Id   varchar(255)

                    ); """
        query2 = """CREATE TABLE SESSIONS (

                    USERNAME VARCHAR(255),

                    UUID VARCHAR(255)

                    ); """

        query3 = """CREATE TABLE LOCKED_FILES (

                    FILE VARCHAR(255)

                    ); """
        self.cursor.execute(query)
        self.cursor.execute(query2)
        self.cursor.execute(query3)
        self.sqliteConnection.commit()



    def passwordResetProtocol(self,name, new_hash,new_user_id):
        self.cursor.execute("UPDATE USERS SET Hash=?, Id=? WHERE Name=?",(new_hash,new_user_id,name,))
        self.sqliteConnection.commit()
