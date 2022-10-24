import os
import sqlite3


class DataBase:

    def __init__(self,database):

        database_exists=os.path.exists(database)

        self.sqliteConnection = sqlite3.connect(database, check_same_thread=False)

        self.cursor = self.sqliteConnection.cursor()

        if not database_exists:
            self.createDatabase()
        else:
            self.purgeDatabase()

    def loadToTMP(self, path):
        records = self.cursor.execute("SELECT * FROM CATALOG WHERE PARENT_PATH = (?)", (path,)).fetchall()
        if not records:
            return False

        for record in records:
            self.addTmpFile(record[1:])

    def pathIN_DB(self, path):
        return any(self.cursor.execute("SELECT PARENT_PATH FROM CATALOG WHERE PARENT_PATH=?",(path,)).fetchall())

    def fileIN_DB(self, file, path):
        return any(self.cursor.execute("SELECT PARENT_PATH, NAME FROM CATALOG WHERE PARENT_PATH=? AND NAME=?",(file,path,)).fetchall())

    def getFiles(self, path):
        return self.cursor.execute("SELECT ID, NAME, TYPE, SIZE, MOD_DATE, CREATION_DATE, COMPRESSED FROM CATALOG WHERE PARENT_PATH=?",(path,)).fetchall()

    def getFilesByName(self, order):
        return self.cursor.execute("SELECT * FROM CATALOG ORDER BY NAME "+order).fetchall()

    def getFilesByType(self, order):
        return self.cursor.execute("SELECT * FROM CATALOG ORDER BY TYPE "+order).fetchall()

    def getFilesBySize(self, order):
        return self.cursor.execute("SELECT * FROM CATALOG ORDER BY SIZE "+order).fetchall()

    def getFilesByModDate(self, order):
        return self.cursor.execute("SELECT * FROM CATALOG ORDER BY MOD_DATE "+order).fetchall()

    def getFilesByCreateDate(self, order):
        return self.cursor.execute("SELECT * FROM CATALOG ORDER BY CREATION_DATE "+order).fetchall()

    def getFileNameByID(self,id):
        return self.cursor.execute("SELECT * FROM CATALOG WHERE ID=?",(id,)).fetchall()


    def fileExists(self, name):
        return self.cursor.execute("SELECT * FROM CATALOG WHERE NAME=?",(name,)).fetchall()
        #self.sqliteConnection.commit()

    def deleteFile(self,path, name):
        self.cursor.execute("DELETE FROM CATALOG WHERE PARENT_PATH=? AND NAME=?",(path, name,))
        self.sqliteConnection.commit()

    def printDatabase(self):
        print(self.cursor.execute("SELECT * FROM CATALOG").fetchall())


    def addFile(self, values):
        self.cursor.execute("INSERT INTO CATALOG VALUES (NULL, ?,?,?,?,?,?,?);",(values[0],values[1],values[2],values[3],values[4],values[5],values[6]))
        self.sqliteConnection.commit()

    def purgeDatabase(self):
        self.cursor.execute("DELETE FROM CATALOG")
        self.sqliteConnection.commit()


    def createDatabase(self):
        query = """CREATE TABLE CATALOG (

                    ID INTEGER PRIMARY KEY,

                    PARENT_PATH NVARCHAR(260),

                    NAME VARCHAR(260),

                    TYPE VARCHAR(260),

                    SIZE INT,

                    MOD_DATE DATE,

                    CREATION_DATE DATE,

                    COMPRESSED VARCHAR(5)

                    );"""
        querry2 = "CREATE UNIQUE CLUSTERED INDEX catalog_index ON TABLE (PARENT_PATH, NAME)"

        self.cursor.execute(query)
        self.sqliteConnection.commit()
