import os
import sqlite3

class personalDatabase:

    def __init__(self,database):
        exists = os.path.exists(database)
        database2 = "2.".join(database.split("."))

        self.sqliteConnection = sqlite3.connect(database, check_same_thread=False)


        self.cursor = self.sqliteConnection.cursor()

        if not exists:
            self.createPersonalDataBase()



    def createPersonalDataBase(self):
        query = """CREATE TABLE CATALOG (
                        NAME    VARCHAR(255),
                        PARENT VARCHAR(255),
                        ITEM VARCHAR(255),
                        TYPE VARCHAR(5),
                        SIZE VARCHAR(255),
                        MODIFICATION_DATE VARCHAR(10),
                        UPLOAD_DATE VARCHAR(10),
                        COMPRESSED VARCHAR(5),
                        NONCE VARCHAR(16)
                );"""
        self.cursor.execute(query)
        self.sqliteConnection.commit()

    def addFileToDB(self, file_id, parent, name, metadata):
        """
        metadata:
        type, size, modification date, upload date, compress, nonce
        """
        if self.getFile(parent, name):
            self.deleteFile(parent, name)

        self.cursor.execute("INSERT INTO CATALOG VALUES (?,?,?,?,?,?,?,?,?);",(file_id, parent, name, metadata[0] , metadata[1], metadata[2], metadata[3], metadata[4], metadata[5],))
        self.sqliteConnection.commit()



    def getFiles(self,  parent):
        return self.cursor.execute("SELECT * FROM CATALOG WHERE PARENT=(?);",(parent,)).fetchall()

    def getFile(self, parent, filename):
        result = self.cursor.execute("SELECT * FROM CATALOG WHERE PARENT=(?) AND ITEM=(?);",(parent,filename,)).fetchall()
        if result:
            return result[0]
        return []

    def deleteFile(self, parent, item):
        self.cursor.execute("DELETE FROM CATALOG WHERE PARENT=(?) AND ITEM=(?);",(parent,item,))
        self.sqliteConnection.commit()


    def isDir(self, parent, name):
        result = self.cursor.execute("SELECT TYPE FROM CATALOG WHERE PARENT=(?) AND ITEM=(?);",(parent,name,)).fetchall()[0][0]
        return result=="DIR"

    def renameItem(self, parent, basename, new_name):
        is_dir = self.isDir(parent,basename)

        self.cursor.execute("UPDATE CATALOG SET ITEM=(?) WHERE PARENT=(?) AND ITEM=(?)", (new_name, parent, basename, ))
        if not is_dir:
            self.sqliteConnection.commit()
            return
        else:
            old_parent = os.path.join(parent, basename)
            new_parent = os.path.join(parent, new_name)
            sql = 'SELECT PARENT, ITEM FROM CATALOG WHERE PARENT LIKE "%s%%"'%(old_parent,)
            records = self.cursor.execute(sql).fetchall()
            for record in records:
                self.cursor.execute("UPDATE CATALOG SET PARENT=(?) WHERE PARENT=(?) AND ITEM=(?)", (new_parent+record[0][len(old_parent):], record[0], record[1],))

        self.sqliteConnection.commit()


    def changeParent(self, item, destination):
        parent = os.path.dirname(item)
        basename = os.path.basename(item)

        is_dir = self.isDir(parent,basename)

        self.cursor.execute("UPDATE CATALOG SET PARENT=(?) WHERE PARENT=(?) AND ITEM=(?)", (destination, parent, basename, ))
        if not is_dir:
            self.sqliteConnection.commit()
            return
        else:
            destination = os.path.join(destination, basename)
            sql = 'SELECT PARENT, ITEM FROM CATALOG WHERE PARENT LIKE "%s%%"'%(item,)
            records = self.cursor.execute(sql).fetchall()
            for record in records:
                self.cursor.execute("UPDATE CATALOG SET PARENT=(?) WHERE PARENT=(?) AND ITEM=(?)", (destination+record[0][len(item):], record[0], record[1],))


            self.sqliteConnection.commit()

    def updateModDate(self, parent, filename, mod_date):
        self.cursor.execute("""
        UPDATE CATALOG
        SET MODIFICATION_DATE = ?
        WHERE PARENT = ? AND ITEM = ?;
        """,(mod_date, parent, filename))
        self.sqliteConnection.commit()
