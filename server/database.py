import os
import sqlite3
from tabulate import tabulate

class DataBase:

    def __init__(self,database):

        database_exists=os.path.exists("database.db")

        self.sqliteConnection = sqlite3.connect(database)

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

    def printDatabase(self):
        users = self.cursor.execute("SELECT * FROM USERS").fetchall()
        users.insert(0,["Username","Hash","User ID"])
        print(tabulate(users, headers='firstrow'))
        print()


    def addUserToDatabase(self, s):
        self.cursor.execute("INSERT INTO USERS VALUES (?,?,?);",(s[0],s[1],s[2],))
        self.sqliteConnection.commit()

    def createDatabase(self):
        query = """CREATE TABLE USERS (

                    Name VARCHAR(255),

                    Hash VARCHAR(255),

                    Id   varchar(255)

                    ); """
        self.cursor.execute(query)
        self.sqliteConnection.commit()



    def passwordResetProtocol(self,name, new_hash,new_user_id):
        self.cursor.execute("UPDATE USERS SET Hash=?, Id=? WHERE Name=?",(new_hash,new_user_id,name,))
        self.sqliteConnection.commit()
