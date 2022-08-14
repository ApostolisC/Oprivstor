import os
import sqlite3


class DataBase:

    def __init__(self,database):

        database_exists=os.path.exists(database)

        self.sqliteConnection = sqlite3.connect(database)

        self.cursor = self.sqliteConnection.cursor()

        if not database_exists:
            self.createDatabase()
        else:
            self.purgeDatabase()

    def getFiles(self):
        return self.cursor.execute("SELECT * FROM FILES").fetchall()

    def getFilesByName(self, order):
        return self.cursor.execute("SELECT * FROM FILES ORDER BY NAME "+order).fetchall()

    def getFilesByType(self, order):
        return self.cursor.execute("SELECT * FROM FILES ORDER BY TYPE "+order).fetchall()

    def getFilesBySize(self, order):
        return self.cursor.execute("SELECT * FROM FILES ORDER BY SIZE "+order).fetchall()

    def getFilesByModDate(self, order):
        return self.cursor.execute("SELECT * FROM FILES ORDER BY MOD_DATE "+order).fetchall()

    def getFilesByCreateDate(self, order):
        return self.cursor.execute("SELECT * FROM FILES ORDER BY CREATION_DATE "+order).fetchall()

    def getFileNameByID(self,id):
        return self.cursor.execute("SELECT * FROM FILES WHERE ID=?",str(id)).fetchall()


    def fileExists(self, name):
        return self.cursor.execute("SELECT * FROM FILES WHERE NAME=?",(name,)).fetchall()
        #self.sqliteConnection.commit()

    def deleteFile(self,name):
        self.cursor.execute("DELETE FROM FILES WHERE NAME=?",(name,))
        self.sqliteConnection.commit()

    def printDatabase(self):
        print(self.cursor.execute("SELECT * FROM FILES").fetchall())

    def addFile(self, values):
        self.cursor.execute("INSERT INTO FILES VALUES (?,?,?,?,?,?,?);",(values[0],values[1],values[2],values[3],values[4],values[5],values[6]))
        self.sqliteConnection.commit()

    def purgeDatabase(self):
        self.cursor.execute("DELETE FROM FILES")
        self.sqliteConnection.commit()

    def createDatabase(self):
        query = """CREATE TABLE FILES (

                    ID INT NOT NULL,

                    NAME VARCHAR(255),

                    TYPE VARCHAR(255),

                    SIZE INT,

                    MOD_DATE DATE,

                    CREATION_DATE DATE,

                    COMPRESSED VARCHAR(5),

                    PRIMARY KEY (ID)

                    ); """
        self.cursor.execute(query)
        self.sqliteConnection.commit()
