import os
import sqlite3

class DataBase:

    def __init__(self,database):
        if not os.path.exists("database"):
            os.mkdir("database")
            os.mkdir(os.path.join("database","FILES"))
            os.mkdir(os.path.join("database","databases"))


        database_exists=os.path.exists("database.db")

        self.sqliteConnection = sqlite3.connect(database, check_same_thread=False)

        self.cursor = self.sqliteConnection.cursor()

        if not database_exists:
            print("\n[+] Creating database...")
            self.createDatabase()


    def createDatabase(self):
        query = """CREATE TABLE USERS (
                        NAME    VARCHAR(255),
                        HASH    VARCHAR(255),
                        ID  VARCHAR(32),
                        SALT    VARCHAR(16),
                        MASTER_PASSWORD  VARCHAR(32),
                        IV  VARCHAR(16),
                        TAG VARCHAR(16),
                        PUBLIC_KEY  VARCHAR(4096),
                        PRIVATE_KEY VARCHAR(4096),
                        NONCE VARCHAR(16)

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

    def getRecords(self):
        return self.cursor.execute("SELECT * FROM USERS").fetchall()

    def userExists(self, user):
        return self.cursor.execute("SELECT * FROM USERS WHERE NAME=?",(user,)).fetchall()

    def userExistsWithID(self, id):
        return self.cursor.execute("SELECT COUNT(*) AS RESULT FROM USERS WHERE Id=?",(id,)).fetchall()[0]

    def getUserSettings(self,user):
        try:
            return self.cursor.execute("SELECT * FROM USERS WHERE Name=?",(user,)).fetchall()[0]

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

    def addUserToDatabase(self, s):
        self.cursor.execute("INSERT INTO USERS VALUES (?,?,?, ?, ?, ?, ?, ?, ?, ?);",(s[0],s[1],s[2],s[3],s[4],s[5],s[6], s[7], s[8], s[9],))
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

    def passwordResetProtocol(self,id, settings):
        try:
            self.cursor.execute("UPDATE USERS SET HASH=?, SALT=?, MASTER_PASSWORD=?, IV=?, TAG=?, PUBLIC_KEY=?, PRIVATE_KEY=?, NONCE=? WHERE ID=?",(settings[4],settings[0],settings[1],settings[2],settings[3],settings[5],settings[6],settings[7], id,))
            self.sqliteConnection.commit()
            return True
        except Exception as e:
            print(e)
            return False
