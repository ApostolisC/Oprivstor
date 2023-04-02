from PyQt5 import uic

from PyQt5.QtWidgets import QWidget, QFileDialog, QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidgetItem, QHeaderView, QHBoxLayout, QStatusBar, QProgressBar, QVBoxLayout, QFrame, QSizePolicy, QSpacerItem, QDesktopWidget, QStyle, QAction, QMenu, QTableWidget, QGraphicsOpacityEffect, QDialog, QListWidgetItem

from PyQt5.QtGui import QFontMetrics, QFont, QIcon, QColor, QCursor, QBrush
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QSize, QEvent, QRect, QVariant
import sys

import re


from Cryptography import Cryptography
import socket
import threading
import os
import tempfile
import gzip
import time
import shutil
import json
from argon2 import hash_password_raw

import traceback
import platform
import subprocess


def getResponse(socket, cr=None, server_public_key=None, private_key=None, exchange_mode=False, verification=False):
    if not exchange_mode:
        r=socket.recv(1024*1024)
        size = cr.decryptMessage(bytes().fromhex(r.decode()), private_key)

        to_send = cr.createMessage(b"0", server_public_key)
    else:
        size = bytes().fromhex(socket.recv(1024).decode())
        to_send=b"0"
    socket.send(to_send)
    size = int(size.decode())
    total=0
    data=b""
    while total<size:
        buffer = socket.recv(1024*1024)
        total+=len(buffer)
        data+=buffer

    return data

class FileDialog(QWidget):

    def __init__(self, folder=False):
        super().__init__()
        self.title = 'Oprivstor - File Manager'
        self.left = 10
        self.top = 10
        self.width = 1040
        self.height = 580
        self.files=None
        self.folder=folder
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        if self.folder:
            self.openFolderNameDialog()
        else:
            self.openFileNameDialog()
        #self.saveFileDialog()

        self.show()

    def openFolderNameDialog(self):
        self.files = QFileDialog.getExistingDirectory(self,"File to Upload", "")

    def openFileNameDialog(self, title="File to Upload"):
        options = QFileDialog.Options()
        #options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,title, "","All Files (*)", options=options)
        self.files=fileName
    def openFileNamesDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        files, _ = QFileDialog.getOpenFileNames(self,"QFileDialog.getOpenFileNames()", "","All Files (*);;Python Files (*.py)", options=options)
        self.files = files

    def saveFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(self,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)
        self.files=fileName

    def getResult(self):
        return self.files

class progressThread(QThread):
    progress_update = pyqtSignal(int, int, str, list)
    locked=[]

    def exchangeKeysWithServer(self, main_connection=True):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((self.server,int(self.server_port)))

        s.send(("EXCHANGE %s"%('' if main_connection else "0")).encode())

        server_public_key = self.cr.getPublicFromPEM(self.getResponseFromServer(socket=s, exchange_mode=True))

        s.send(self.cr.createMessage(self.public_pem, server_public_key))


        if main_connection:
            self.s=s
            self.server_public_key=server_public_key

            response = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key).decode().split()

            self.greeting=' '.join(response[:-1])
            self.command_uuid = response[-1]
            return self.command_uuid
        else:
            s.recv(1024)
            return s, server_public_key
    """def getResponseFromServer(self, socket=False, exchange_mode=False, items=None):
        if not socket: socket=self.s
        if not exchange_mode:
            r=socket.recv(1024*1024)
            size = self.cr.decryptMessage(bytes().fromhex(r.decode()), self.private_key)

            to_send = self.cr.createMessage(b"0", self.server_public_key)
        else:
            size = bytes().fromhex(socket.recv(1024).decode())
            to_send=b"0"
        socket.send(to_send)
        size = int(size.decode())
        total=0
        data=b""
        while total<size:
            buffer = socket.recv(1024*1024)
            total+=len(buffer)
            data+=buffer

        return data"""

    def getResponseFromServer(self, socket=False, exchange_mode=False, items=None):
        if not socket: socket = self.s
        if not exchange_mode:
            return getResponse(socket, self.cr, server_public_key=self.server_public_key, private_key=self.private_key, exchange_mode=False, verification=None)
        else:
            return getResponse(socket, None, None, None, True, None)


    def verifyName(self, tmp):
        name = tmp.split(".", maxsplit=1)
        ext = name[-1]
        name = ".".join(name[:-1])+"  "
        i=2
        while os.path.exists(tmp):
            name=name[:-len(str(i-1))-1]+"_"+str(i)
            tmp=name+"."+ext
            i+=1
        return tmp
    ####Compression
    def compressFile(self,path,basepath):
        self.progress_update.emit(self.id, 0, "Compressing...",[""])
        tmp='%s/Oprivstor/%s.gz'%(self.settings["temp-folder"],basepath)

        tmp = self.verifyName(tmp)

        size=os.path.getsize(path)
        with open(path, 'rb') as f:
            with open(tmp, 'wb') as f2:
                while f.tell()<size:
                    f2.write(gzip.compress(f.read(1024*64)))
                    self.progress_update.emit(self.id, int((f.tell()/size)*100), "", [""])


        return tmp

    def decompressFile(self,path,dest):
        dest=self.verifyName(dest)
        self.progress_update.emit(self.id, 0, "Decompressing...", [""])
        size=os.path.getsize(path)
        with gzip.open(path, 'rb') as f:
            with open(dest, 'wb') as f2:
                data=f.read(1024*64)
                while data:
                    f2.write(data)
                    self.progress_update.emit(self.id, int((f.tell()/size)*100), "", [""])
                    data=f.read(1024*64)

        os.remove(path)
        return dest

    ####Encryption
    def encryptFile(self, file):
        self.progress_update.emit(self.id, 0, "Encrypting...", [""])
        buffer_size=1024
        tmp_file="%s/Oprivstor/%s.arc"%(self.settings["temp-folder"],os.path.basename(file))
        tmp_file = self.verifyName(tmp_file)
        with open(file, "rb") as f:
            size = os.path.getsize(file)
            with open(tmp_file,"wb") as encrypted_file:
                nonce = os.urandom(12)
                data = f.read(buffer_size)
                while data:
                    encrypted = self.cr.encryptFileChaCha20Poly1305(data, self.master_passwd, nonce)
                    encrypted_file.write(encrypted)
                    self.progress_update.emit(self.id, int((f.tell()/size)*100), "", [""])
                    data = f.read(buffer_size)


        return tmp_file, nonce.hex()

    def decryptFile(self,file, nonce):
        self.progress_update.emit(self.id, 0, "Decrypting...", [""])
        dest = ".".join(file.split(".")[:-1])
        nonce = bytes().fromhex(nonce)
        # Encrpyt will use 1024 buffer but chacha20poly1305 will generate and a tag of size 16
        # so 1024 + 16
        size = os.path.getsize(file)
        buffer_size=1040
        with open(file, "rb") as f:
            with open(dest,"wb") as decrypted_file:
                data = f.read(buffer_size)
                while data:
                    decrypted = self.cr.decryptChaCha20Poly1305(data, self.master_passwd, nonce)
                    decrypted_file.write(decrypted)
                    self.progress_update.emit(self.id, int((f.tell()/size)*100), "", [""])
                    data = f.read(buffer_size)


        os.remove(file)

        return dest
    def __init__(self, id, info, extra, action, current_job):
        QThread.__init__(self)
        self.id = id
        self.action = action
        self.info = info

        self.command_uuid, \
        self.username, \
        self.server_public_key, \
        self.settings, \
        self.server, \
        self.server_port, \
        self.master_passwd = extra

        self.current_job = current_job

        self.cr = Cryptography()
        self.private_key,public_key, self.public_pem = self.cr.createRSAKeysWithPem()


    def run(self):
        while self.id!=self.current_job[0]:
            time.sleep(0.2)
        filename = self.info[1]

        if self.action=="download":
            try:
                full_path=os.path.join(self.info[0], filename)
                self.locked.append(full_path)

                command = ("DOWNLOAD %s"%(full_path.encode().hex()))
                message = "%s %s %s"%(self.command_uuid, self.username, command)

                s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

                s.send(self.cr.createMessage(message.encode(), server_public_key))

                result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

                if result=="1":
                    return

                info = self.cr.decryptMessage(self.getResponseFromServer(s),self.private_key).decode()
                if info[0]=="1":
                    s.close()
                    return
                _, file_size, compressed, nonce = info.split()
                #filename = bytes().fromhex(filename).decode()

                file_size = int(file_size)

                path = os.path.join(self.settings["download-folder"],filename)

                if not os.path.exists(self.settings["temp-folder"]):
                    os.mkdir(self.settings["temp-folder"])

                tmp_file= os.path.join(self.settings["temp-folder"], "Oprivstor","%s.arc"%os.path.basename(path))

                s.send(self.cr.createMessage(b"0", self.server_public_key))

                t0=time.time()
                self.progress_update.emit(self.id, 0, "Downloading...", [""])
                with open(tmp_file,"wb") as f:
                    total=0
                    buffer_size = 1024#*1024*8
                    buffer = s.recv(buffer_size)
                    while buffer and total<file_size:
                        total+=len(buffer)
                        f.write(buffer)
                        self.progress_update.emit(self.id, int((total/file_size)*100),"",[""])
                        if total==file_size:
                            break
                        buffer = s.recv(buffer_size)

                s.close()
                time.sleep(1)
                tmp_file=self.decryptFile(tmp_file,nonce)

                if compressed=="True":
                    time.sleep(1)
                    dest = self.decompressFile(tmp_file, path)
                else:
                    path = self.verifyName(path)
                    shutil.move(tmp_file, path)
                    dest = path
                    os.remove(tmp_file)
                time.sleep(1)
                self.progress_update.emit(self.id, 100, "Done", [""])

                time.sleep(1)
                self.progress_update.emit(self.id, -1, "", [dest])

                self.locked.remove(full_path)

            except Exception as e:
                if full_path in self.locked:
                    self.locked.remove(full_path)

                traceback.print_exc()

        else:
            """
            upload
            """
            full_path=os.path.join(self.info[0].name, filename)
            self.locked.append(full_path)

            parent_dir, file_to_upload, size, new_name, compress = self.info
            name = os.path.basename(os.path.normpath(file_to_upload)) if not new_name else new_name

            file_type="FILE"

            encoded_filename=os.path.join(parent_dir.getFullPath(), name).encode().hex()

            command= ("UPLOAD %s %s %s"%(encoded_filename, "FILE", compress))
            message = "%s %s %s"%(self.command_uuid, self.username, command)

            s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

            s.send(self.cr.createMessage(message.encode(), server_public_key))

            result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()


            if result=="1":
                s.close()
                return

            if compress:
                compressed_file = self.compressFile(file_to_upload,name)

                size = os.path.getsize(compressed_file)

                file_to_upload = compressed_file

            time.sleep(1)

            file_to_upload, nonce = self.encryptFile(file_to_upload)
            
            if compress: os.remove(compressed_file)

            size = os.path.getsize(file_to_upload)


            try:
                time.sleep(1)
                self.progress_update.emit(self.id, 0, "Uploading...", [""])

                s.send(self.cr.createMessage(("%s %s"%(str(size), nonce)).encode(),self.server_public_key))

                response=self.cr.decryptMessage(s.recv(1024), self.private_key).decode()
                if response!="0":
                    print(response[1:])
                    return

                with open(file_to_upload, "rb") as f:
                    buffer_size=1014#*1024*2
                    while f.tell()<size:
                        s.sendfile(f,f.tell(),buffer_size)
                        self.progress_update.emit(self.id, int((f.tell()/size)*100), "", [""])


                metadata = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()


                time.sleep(1)
                self.progress_update.emit(self.id, 100, "Done", [""])

                self.progress_update.emit(self.id, -1, metadata, [parent_dir])


            except BrokenPipeError:
                print("\n[!] Lost connection. Upload Canceled.")
            finally:
                self.locked.remove(full_path)
                os.remove(file_to_upload)
            return

class UploadFileUI(QMainWindow):
    upload_signal = pyqtSignal(list)
    def __init__(self, directory, filename, exists, files, styles):
        super(UploadFileUI, self).__init__()
        uic.loadUi(os.path.join("ui","oprivstor_upload.ui"), self)

        self.setStyleSheet("background-color: %s; color: %s"%(styles["main_background"], styles["main_color"]))
        self.exists_label.setStyleSheet("color:%s"%styles["upload_settings_file_exists"])
        self.overwrite.setStyleSheet("color: %s"%styles["upload_settings_overwrite"])

        for v in (self.dir, self.file, self.dir_label, self.file_label):
            v.setStyleSheet("color: %s"%styles["upload_settings_secondary_color"])

        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())


        self.filename = filename
        self.files = files
        self.exists = exists

        self.dir.setText(directory)
        self.file.setText(os.path.basename(filename))

        if not self.exists:
            self.exists_label.setVisible(False)
            self.overwrite.setVisible(False)
        else:
            self.upload_button.setEnabled(False)

        self.new_name.textChanged.connect(self.validate_name)

        self.upload_button.clicked.connect(self.returnResponse)
        self.cancel_button.clicked.connect(self.cancel)
        self.overwrite.stateChanged.connect(self.overwriteStateChangedEvent)


    def returnResponse(self):
        if not self.exists:
            self.upload_signal.emit([True, self.filename, self.new_name.text(), self.compress.isChecked()])
        else:
            self.upload_signal.emit([self.filename, self.new_name.text(), self.overwrite.isChecked(),self.compress.isChecked()])

        self.close()

    def cancel(self):
        self.upload_signal.emit([False])
        self.close()

    def overwriteStateChangedEvent(self, a):
        if not a:
            font=self.new_name.font()
            font.setStrikeOut(False)
            self.new_name.setFont(font)

            if self.validate_name():
                self.upload_button.setEnabled(True)
            else:
                self.upload_button.setEnabled(False)
        else:
            font=self.new_name.font()
            font.setStrikeOut(True)
            self.new_name.setFont(font)
            self.upload_button.setEnabled(True)

    def validate_name(self):
        value = self.new_name.text()
        if not value:
            if not self.exists:
                self.overwrite.setEnabled(False)
            else:
                if not self.overwrite.isEnabled():
                    self.upload_button.setEnabled(False)
            return
        self.overwrite.setEnabled(True)
        l = len(value)
        i=0
        while i<len(self.files) and len(self.new_name.text())==l:
            if self.files[i].name==value:
                self.new_name.setStyleSheet("color: rgb(224, 27, 36)")

                self.upload_button.setEnabled(False)
                return False
            i+=1

        if i==len(self.files):
            self.new_name.setStyleSheet("color: rgb(1, 208, 12)")

            self.upload_button.setEnabled(True)
            return True
        self.new_name.setStyleSheet("color: rgb(224, 27, 36)")

        return False

class Rename(QMainWindow):
    rename_signal = pyqtSignal(list, str, str)
    update_bar = pyqtSignal(int)

    def closeEvent(self, event):
        self.parent.setEnabled(True)

        event.accept()


    def __init__(self, parent, parent_path, item):
        super(Rename, self).__init__()

        self.parent = parent
        self.parent_path = parent_path
        self.item = item
        self.full_path = os.path.join(parent_path.getFullPath(), item)

        uic.loadUi(os.path.join("ui","oprivstor_rename.ui"), self)
        self.setStyles()

        self.frame.setVisible(False)

        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        self.title.setText(self.full_path)
        self.error.setVisible(False)

        self.new_name.textChanged.connect(self.validateName)
        self.rename.clicked.connect(self.renameItem)
        self.return_2.clicked.connect(lambda: self.close())
        self.update_bar.connect(self.updateBar)

        self.show()

    def validateName(self):
        for file in self.parent_path.files:
            if file.name==self.new_name.text():
                self.new_name.setStyleSheet("color: %s"%self.parent.styles["error"])
                self.rename.setEnabled(False)
                self.error.setVisible(True)
                return
        self.error.setVisible(False)
        self.new_name.setStyleSheet("color: %s;"%self.parent.styles["validation"])
        self.rename.setEnabled(True)

        self.command_label.setStyleSheet("color: %s;"%self.parent.styles["main_color"])

    def updateBar(self, value):
        if value==-1:
            self.progressBar.setInvertedAppearance(True)
        elif value==-2:
            self.progressBar.setInvertedAppearance(False)
        else:
            self.progressBar.setValue(value)


    def waitLoop(self, status, thread=False):
        if not thread:
            a=threading.Thread(target=self.waitLoop, args=(status, True,))
            a.daemon=True
            a.start()
            return

        value=0
        pr = 1
        while status[0]==0:
            time.sleep(0.1)
            value+=10*pr
            self.update_bar.emit(value)
            if value==100:
                self.update_bar.emit(-1)
                pr*=(-1)
            elif value==0:
                self.update_bar.emit(-2)
                pr*=(-1)


        if status[0]==1:
            self.close()
        else:
            self.error2.setText("Command failed. Server timed out.")
            self.return_2.setVisible(True)

    def renameItem(self):
        new_name = self.new_name.text()
        old_name = self.title.text()

        self.frame.setVisible(True)
        self.return_2.setVisible(False)

        status=[0]
        self.waitLoop(status)
        self.parent.executeRenameItem(self.parent_path, old_name, new_name, status)


    def setStyles(self):
        self.setStyleSheet("background-color: %s; color: %s"%(self.parent.styles["main_background"],self.parent.styles["main_color"]))

        for v in (self.label, self.title):
            v.setStyleSheet("color: %s"%self.parent.styles["menu"])

        style = """
        QPushButton:hover {
            color:%s;
            background-color:%s;
        }
        QPushButton {
            color: %s;
            background-color: %s;
        }
        """%(self.parent.styles["main_background"], self.parent.styles["button_hover"],self.parent.styles["button_color"], self.parent.styles["main_background"])
        for v in (self.cancel, self.rename):
            v.setStyleSheet(style)

        self.error.setStyleSheet("color: %s"%self.parent.styles["error"])

class moveItems(QMainWindow):
    resized = pyqtSignal()

    def resizeEvent(self, event):
        self.resized.emit()
        return super(moveItems, self).resizeEvent(event)

    def resizeWindow(self):
        self.verticalFrame.resize(self.width(), self.height())

    def closeEvent(self, event):
        self.parent.setVisible(True)

        event.accept()

    def __init__(self, current_path, name, parent):
        super(moveItems, self).__init__()
        uic.loadUi(os.path.join("ui","move_files2.ui"), self)

        self.setStyleSheet("background-color: %s; color: %s"%(parent.styles["main_background"], parent.styles["main_color"]))

        table_style="background-color: %s; color: %s;selection-background-color: %s;"%(parent.styles["table"],parent.styles["table_items"],parent.styles["table_selection"] )
        self.table.setStyleSheet(table_style)


        style = """
        QPushButton:hover {
            color:%s;
            background-color:%s;
        }
        QPushButton {
            color: %s;
            background-color: %s;
        }
        """%(parent.styles["main_background"], parent.styles["button_hover"],parent.styles["button_color"], parent.styles["main_background"])
        for v in (self.cancel, self.move_button, self.back_button,):
            v.setStyleSheet(style)

        self.label.setStyleSheet("color: %s"%parent.styles["menu"])
        self.title.setStyleSheet("color: %s"%parent.styles["menu"])
        self.label_2.setStyleSheet("color: %s"%parent.styles["move_item_sec_title"])
        self.current_path_box.setStyleSheet("color: %s"%parent.styles["move_item_sec_title"])


        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())


        self.current_path = current_path
        self.main_path = current_path
        self.name = name
        self.parent = parent
        self.buttons_table=[]

        self.title.setText(name)
        self.current_path_box.setText(self.current_path.getFullPath())

        self.move_button.clicked.connect(self.moveFiles)
        self.cancel.clicked.connect(self.close)
        self.back_button.clicked.connect(self.goBack)

        self.table.doubleClicked.connect(self.openItem)

        self.show()

        self.loadFilesToGui()

    def loadFilesToGui(self):
        self.buttons_table.clear()
        if self.current_path.parent==None:
            self.back_button.setVisible(False)
        else:
            self.back_button.setVisible(True)
        self.table.setRowCount(0)
        current_row=-1
        for i in range(0, len(self.current_path.files)):
            item_info = self.current_path.files[i].getInfo()

            current_row+=1

            self.table.insertRow(current_row)
            for j in range(6):
                if j==1:
                    item = self.parent.getTypeButton(item_info[j])
                    item.setEnabled(False)
                    if item_info[2]!="-":
                        item.setStyleSheet("background-color: %s;border: 0px;"%self.parent.styles["move_item_table_disabled_item"])

                    if self.main_path==self.current_path:
                        if os.path.join(self.current_path.getFullPath(), item_info[0])==self.title.text():

                            item.setStyleSheet("background-color: #A18C2F; border: 0px")
                    self.table.setCellWidget(current_row, j, item)
                    self.buttons_table.append(item)
                else:
                    item=QTableWidgetItem(item_info[j])
                    if item_info[2]!="-":
                        flags=item.flags()
                        flags &= ~Qt.ItemIsSelectable
                        item.setFlags(flags)
                        item.setBackground(QColor(self.parent.styles["move_item_table_disabled_item"]))
                    if self.main_path==self.current_path:
                        if os.path.join(self.current_path.getFullPath(), item_info[0])==self.title.text():
                            flags=item.flags()
                            flags &= ~Qt.ItemIsSelectable
                            item.setFlags(flags)
                            item.setBackground(QColor("#A18C2F"))
                    self.table.setItem(current_row, j, item)
        self.table.resizeColumnsToContents()

    def openItem(self):
        info = [v.text() for v in self.table.selectedItems()]

        if not info:return

        if info[1]=="-": # not size. we cant get type because we retreive selected ITEMS and type if a widget

            i=0
            while not self.current_path.files[i].name == info[0]:
                i+=1
            item = self.current_path.files[i]
            self.current_path = item
            self.current_path_box.setText(item.getFullPath())
            if not self.current_path.visited:
                self.parent.getFiles(self.current_path)
                self.current_path.visited = True
            self.loadFilesToGui()
            return

    def goBack(self):
        if not self.current_path.parent: return

        self.current_path = self.current_path.parent

        if self.current_path.name=="/":
            self.back_button.setVisible(False)
        else:
            self.back_button.setVisible(True)

        self.current_path_box.setText(self.current_path.getFullPath())

        self.loadFilesToGui()

    def moveFiles(self):
        destination = self.current_path_box.text()
        if self.main_path==self.current_path:
            self.parent.showError("Error: Cannot move to '%s' . Already exists in destination."%destination)
            self.close()
            return
        self.parent.moveItem(self.title.text(), destination, self.current_path)
        self.close()

class Settings(QDialog):
    def __init__(self, username, parent, settings):
        super(Settings, self).__init__()
        self.parent = parent
        uic.loadUi(os.path.join("ui","oprivstor_settings.ui"), self)

        self.username_field.setText(username)

        self.change_password_button.clicked.connect(self.changePassword)
        self.new_password.textChanged.connect(self.verifyPasswords)
        self.new_password_verify.textChanged.connect(self.verifyPasswords)
        self.current_password.textChanged.connect(self.verifyPasswords)

        self.tmp_folder_field.setText(settings["temp-folder"])
        self.download_folder_field.setText(settings["download-folder"])

        self.open_temp_button.setIcon(self.style().standardIcon(getattr(QStyle, "SP_DirOpenIcon")))
        self.open_download_button.setIcon(self.style().standardIcon(getattr(QStyle, "SP_DirOpenIcon")))

        self.tmp_folder_field.setCursorPosition(0)
        self.download_folder_field.setCursorPosition(0)

        pixmapi = getattr(QStyle, "SP_FileDialogInfoView")
        icon = self.style().standardIcon(pixmapi)


        self.setStyleSheet("background-color: %s; color: %s"%(parent.styles["main_background"], parent.styles["main_color"]))

        for v in (self.label, self.label_7):
            v.setStyleSheet("color:%s"%parent.styles["settings_title"])

        self.error_message.setStyleSheet("color: %s"%parent.styles["settings_passwd_error_message"])

        self.label_4.setStyleSheet("color: %s"%parent.styles["error"])


        self.change_password_button.setEnabled(False)

        self.open_temp_button.clicked.connect(lambda: self.setSettings(FileDialog(folder=True).getResult(), 0))
        self.open_download_button.clicked.connect(lambda: self.setSettings(FileDialog(folder=True).getResult(), 1))

        self.save_button.clicked.connect(self.writeSettings)

    def setSettings(self, path, mode):
        if not path:return
        if not mode:
            self.tmp_folder_field.setText(path)
        else:
            self.download_folder_field.setText(path)

    def writeSettings(self):
        with open(".settings", "w") as f:
            f.write("{\"download-folder\": \"%s\", \"temp-folder\": \"%s\"}"%(self.download_folder_field.text(),self.tmp_folder_field.text()))

        self.parent.readSettings()
        self.close()

    def verifyPasswords(self):
        if self.current_password.text()!=self.parent.password:
            self.error_message.setText("Invalid Password")
            self.change_password_button.setEnabled(False)
            return
        if self.new_password.text()!=self.new_password_verify.text():
            self.error_message.setText("New password does not match")
            color = "red"
            self.change_password_button.setEnabled(False)
        else:
            self.error_message.setText("")
            color = "#6D4AFF"
            if self.current_password.text():
                if self.current_password.text()==self.new_password.text():
                    self.error_message.setText("New password cannot be the same as the old one")
                    return
                elif len(self.new_password.text()) in range(1,8):
                    self.error_message.setText("Password must be 8-256 characters long")
                    return
                self.change_password_button.setEnabled(True)

        for v in (self.new_password, self.new_password_verify):
            v.setStyleSheet("color: %s"%color)

    def changePassword(self):
        self.parent.changePassword(self.new_password.text())
        self.error_message.setStyleSheet("color: green")
        self.error_message.setText("Password Changed!")

class showError(QThread):
    update = pyqtSignal(str, float)
    error=None
    turn=0
    def __init__(self):
        QThread.__init__(self)

    def setError(self, error):
        showError.turn+=1
        self.my_turn = showError.turn
        self.error = error


    def run(self):

        self.update.emit(self.error, 1)

        for i in range(25):
            time.sleep(0.2)
            if not showError.turn==self.my_turn:
                return

        for i in range(11):
            if not showError.turn==self.my_turn:
                return
            self.update.emit(self.error, 1-i/10)
            time.sleep(0.1)

class Preferences(QMainWindow):
    solarized_style = {"name": "Solarized",

    "main_background": "#002b36",
    "secondary_background":"#002b36",
    "main_color": "#fdf6e3",
    "status_bar": "#002b36",
    "status_bar_items": "#fdf6e3",
    "progressbar": "#268bd2",
    "scroll_area": "#586e75",
    "table": "#073642",


    "table_selection": "#2aa198",
    "table_items": "#fdf6e3",
    "button_color": "#fdf6e3",
    "button_hover": "#268bd2",
    "dark_button_background":"#262F37",
    "button_background":"#002b36",
    "button_background_hover":"#268bd2",

    "menu": "#b58900",
    "search_bar": "#93a1a1",
    "line": "#b58900",
    "circle": "#b58900",
    "circle_background": "#2aa198", "settings_title": "#b58900",
    "settings_passwd_error_message": "#6c71c4",
    "upload_settings_file_exists": "#b58900", "upload_settings_overwrite": "#dc322f",
    "upload_settings_secondary_color": "#6c71c4", "move_item_title2": "#fdf6e3", "move_item_sec_title": "#6c71c4",
    "move_item_table_disabled_item": "#586e75",
    "validation": "#859900",
    "warning": "#cb4b16", "error": "#dc322f"}

    carbon_style = {"name":"Carbon",
    "main_background": "#16141C",
    "secondary_background":"#302C3D",
     "main_color": "#FFFFFF",
     "status_bar": "#16141C",
    "status_bar_items":"#fdf6e3" ,
    "progressbar":"#268bd2" ,
    "scroll_area": "#292733",
    "table": "#1C1B24",
    "table_selection": "#6D4AFF",
    "table_items": "#FFFFFF",
    "menu":"#6D4AFF",
    "search_bar":"#E5A50A",

    "button_background":"#292733",

    "button_color": "#FFFFFF",
    "button_hover":"#6D4AFF",

    "button_background_hover":"#6D4AFF" ,
    "line":"#6D4AFF",
    "circle":"#6D4AFF",
    "circle_background":"#292733",
    "error":"red",
    "settings_title":"#E5A50A",
    "settings_passwd_error_message":"#6D4AFF",
    "upload_settings_file_exists":"#E5A50A",
    "upload_settings_overwrite":"#C01C28",
    "upload_settings_secondary_color":"#6D4AFF",
    "move_item_title2":"#6D4AFF",
    "move_item_sec_title": "#E5A50A",
    "move_item_table_disabled_item":"#292733",
    "validation":"#859900",
    "warning":"#cb4b16"}


    def __init__(self, parent):
        if not parent:return
        super(Preferences, self).__init__()
        uic.loadUi(os.path.join("ui","oprivstor_preferences.ui"), self)

        self.parent = parent

        self.add_button.clicked.connect(self.getFile)
        self.save_style_button.clicked.connect(self.validateStyle)
        self.style_edit.textChanged.connect(lambda: self.textChanged())

        self.style_box.currentIndexChanged.connect(self.styleBoxLineChanged)

        self.setStyleSheet("background-color: %s; color:%s;"%(parent.styles["table"],parent.styles["main_color"]))
        self.validation_status.setStyleSheet("color: %s"%self.parent.styles["error"])

        self.add_button.setStyleSheet("background-color: %s"%self.parent.styles["secondary_background"])
        self.tab.setStyleSheet("background-color: %s"%self.parent.styles["secondary_background"])

        self.tabWidget.setStyleSheet("QTabBar::tab {background: %s;width: 100px; height: 26px; border-radius: 13px; border: none}"%self.parent.styles["secondary_background"])

        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        style_name = parent.styles["name"]
        self.label.setText("Curent Theme: %s"%style_name)
        for i in range(self.style_box.count()):
            if self.style_box.itemText(i)==style_name:
                self.style_box.setCurrentIndex(i)
                break

    def styleBoxLineChanged(self, i):
        enabled=False
        #if i+1 == self.style_box.count():
        #    enabled=True
        #    self.save_style_button.setText("Validate")
        #else:
        if True:
            self.save_style_button.setText("Save")
        for v in (self.label_3, self.add_button, self.file, self.style_edit):
            v.setEnabled(enabled)

    def getFile(self):
        self.validation_status.setText("")

        fd = FileDialog()
        file = fd.getResult()
        if not file: return

        self.style_edit.setPlainText("")
        self.save_style_button.setText("Save")


        try:
            self.style_edit.setPlainText(open(file,"r").read())
            self.file.setText(file)
        except UnicodeDecodeError:
            self.validation_status.setText("Invalid file encoding")

    def saveStyle(self):
        if self.style_box.currentText() in ("Solarized", "Carbon"):
            with open(".styles","w") as f:
                f.write(self.style_box.currentText())
            self.parent.readSettings()
            self.parent.setStyles()

    def textChanged(self):
        self.save_style_button.setText("Validate")
        self.validation_status.setText("")

    def validateStyle(self):
        if self.save_style_button.text()=="Save":
            self.saveStyle()
            self.close()
        self.unknown.clear()
        self.missing.clear()
        self.validation_status.setStyleSheet("color: %s"%self.parent.styles["error"])
        try:
            error=False

            styles = json.loads(self.style_edit.toPlainText())

            keys = list(self.parent.styles.keys())
            keys2 = keys.copy()
            values=list(styles.keys())

            for key in keys:
                found=False
                for value in values:
                    if key==value:
                        if key!="name":
                            if not re.search(r'^#(?:[0-9a-fA-F]{3}){1,2}$', styles[value]):
                                self.validation_status.setText("Invalid hex value for key: %s"%value)
                                return

                        found=True
                        values.remove(value)
                        keys2.remove(value)
                if not found:
                    error = True



            for value in values:
                if not re.search(r'^#(?:[0-9a-fA-F]{3}){1,2}$', styles[value]):
                    self.validation_status.setText("Invalid hex value for unknown key: %s"%value)
                    return
                item=QListWidgetItem(value)
                self.unknown.addItem(item)

            if values:
                self.unknown.setStyleSheet("background-color:%s"%self.parent.styles["secondary_background"])
            else:
                self.unknown.setStyleSheet("background-color:%s"%self.parent.styles["main_background"])

            if keys2:
                self.missing.setStyleSheet("background-color:%s"%self.parent.styles["secondary_background"])
            else:
                self.missing.setStyleSheet("background-color:%s"%self.parent.styles["main_background"])

            for value in keys2:
                item=QListWidgetItem(value)
                self.missing.addItem(item)

            if not error:
                if not values:
                    self.validation_status.setStyleSheet("color: %s"%self.parent.styles["validation"])
                else:
                    self.validation_status.setStyleSheet("color: %s"%self.parent.styles["warning"])

                self.validation_status.setText("Validated")
                self.save_style_button.setText("Save")
                self.styles = styles
            else:
                self.validation_status.setText("Keys missing")



        except json.decoder.JSONDecodeError:
            self.validation_status.setText("Invalid json format")

class LoadFilesToGui(QThread):
    add_row = pyqtSignal(list)
    def __init__(self):
        QThread.__init__(self)


    def getTypeButton(self, type):
        item=QPushButton()
        item.setText(type)
        item.setStyleSheet("color:white;background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0.01, y2:0, stop:1 rgba(255, 255, 255, 0));border: none;")

        if type=="DIR":
            name="SP_DirIcon"
        elif type=="FILE":
            name="SP_FileIcon"
        elif type=="DIROPEN":
            name="SP_DirOpenIcon"
        pixmapi = getattr(QStyle, name)
        icon = self.style().standardIcon(pixmapi)
        item.setIcon(icon)
        return item

    def setFiles(self, files):
        self.files = files

    def setStyle(self, style):
        self.style = style

    def run(self):

        self.add_row.emit(["0"])

        for file in self.files:
            item_info = file.getInfo()
            self.add_row.emit(item_info)

        self.add_row.emit([])

class Ui(QMainWindow):
    resized = pyqtSignal()
    load_files = pyqtSignal()
    rename_signal = pyqtSignal(str)
    #show_error = pyqtSignal(str)

    def eventFilter(self, source, event):
        if (event.type() == QEvent.MouseButtonPress and event.buttons() == Qt.RightButton and source is self.table.viewport()):
            item = self.table.itemAt(event.pos())
            if item is not None:
                self.menu = QMenu(self)
                self.menu.setStyleSheet("color: white")
                item = self.table.item(item.row(),0)

                self.action_move = self.menu.addAction("Move")
                self.action_move.triggered.connect(lambda: self.openMoveItemsWindow(item.text()))

                self.action_rename = self.menu.addAction("Rename")
                self.action_rename.triggered.connect(lambda: self.openRenameWindow(item.text()))

        return super(Ui, self).eventFilter(source, event)

    def generateMenu(self, pos):
        try:
            self.menu.exec_(self.table.mapToGlobal(pos))
        except AttributeError:
            pass



    def setStyles(self):
        self.setStyleSheet("background-color: %s; color: %s"%(self.styles["main_background"],self.styles["main_color"]))
        self.statusBar.setStyleSheet("background-color: %s"%self.styles["status_bar"])
        self.progressArea.setStyleSheet("background-color: %s"%self.styles["scroll_area"])

        # error here
        table_style="QTableWidget::item:selected{color: %s } QTableWidget { background-color: %s; color: %s;selection-background-color: %s; }  QHeaderView::section{background-color:%s};"%(self.styles["main_color"], self.styles["table"], self.styles["table_items"],self.styles["table_selection"],self.styles["table"])
        self.table.setStyleSheet(table_style)
        font = QFont("verdana", 10)
        self.table.setFont(font)


        style = """
        QPushButton:hover {
            color:%s;
            background-color:%s;
        }
        QPushButton {
            color: %s;
            background-color: %s;
        }
        """%(self.styles["button_color"], self.styles["button_background_hover"],self.styles["button_color"], self.styles["button_background"])
        for v in (self.upload_button, self.download_button, self.delete_button, self.back_button, self.create_button, self.cancel_new_dir_button):
            v.setStyleSheet(style)

        self.search_bar.setStyleSheet("color: %s;"%self.styles["search_bar"])

        self.menubar.setStyleSheet("color: %s;"%self.styles["menu"])

        for i in range(6):
            font = QFont("Arial Black",9)
            item = self.table.horizontalHeaderItem(i)
            item.setForeground(QColor("white"));
            item.setBackground(QColor(self.styles["table"]))
            item.setFont(font)
        #item.setBackground(QColor("blue"));
        #item.setData(Qt.BackgroundRole,QBrush(QColor("black")));


        #st = "::section{background-color:rgb(190,1,1)}"
        #item = self.table.horizontalHeaderItem(0)
        #item.setBackground(QColor("rgb(190,1,1)"))
        #self.table.setHorizontalHeaderItem(0,item)

    def loadUi(self):
        uic.loadUi(os.path.join("ui","oprivstor_ui.ui"), self)


        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        header = self.table.horizontalHeader()
        for i in range(6):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)

        self.mainProgressWidget = QWidget()
        self.vlayout = QVBoxLayout()
        self.mainProgressWidget.setLayout(self.vlayout)
        self.progressArea.setWidget(self.mainProgressWidget)

        self.download_button.clicked.connect(self.openItem)
        self.upload_button.clicked.connect(self.uploadFile)
        self.back_button.clicked.connect(self.backEvent)
        self.delete_button.clicked.connect(self.deleteFile)
        self.search_bar.textChanged.connect(self.searchFiles)
        self.table.itemSelectionChanged.connect(self.changedRowEvent)
        self.table.doubleClicked.connect(self.openItem)

        self.action_upload_file.triggered.connect(self.uploadFile)
        self.action_create_directory.triggered.connect(self.createDirAction)
        self.action_delete_file.triggered.connect(self.deleteFile)
        self.actionProgress_Status.triggered.connect(self.toggleProgressArea)
        self.actionClear_Completed_Actions.triggered.connect(self.clearCompletedProgresses)
        self.action_preferences.triggered.connect(self.openPreferencesWindow)
        #self.action_create_directory.setIcon(self.style().standardIcon(getattr(QStyle, "SP_FileDialogNewFolder")))
        #self.action_upload_file.setIcon(QIcon("icons/new_file.png"))

        self.settings_action = QAction("Settings",self)
        self.settings_action.triggered.connect(self.openSettings)
        self.menubar.addAction(self.settings_action)

        self.create_button.clicked.connect(self.createButtonClicked)
        self.new_dir.textChanged.connect(self.newDirChangedEvent)
        self.cancel_new_dir_button.clicked.connect(self.cancelCreateDir)
        self.create_button.setEnabled(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.generateMenu)
        self.table.viewport().installEventFilter(self)


        self.statusBar = QStatusBar()
        self.statusBarLayout = QHBoxLayout(self.statusBar)
        self.statusBarLayout.addStretch(0)
        self.statusBarLayout.addWidget(self.progressArea)
        self.statusBarLayout.addStretch(1)
        self.statusBar.setLayout(self.statusBarLayout)
        self.setStatusBar(self.statusBar)

        l = QHBoxLayout()
        l.addItem(QSpacerItem(0, 40, QSizePolicy.Minimum))
        w=QWidget()

        w.setLayout(l)
        self.statusBar.insertPermanentWidget(0, w,0)
        self.statusBar.insertPermanentWidget(1, self.progressArea, 1)
        self.statusBar.setFixedSize(self.width()-20, 125)

        self.back_button.setVisible(False)

        self.show_pb.clicked.connect(lambda: self.toggleProgressArea(1))
        self.statusbar_raise_frame.enterEvent = self.enterFrame
        self.statusbar_raise_frame.leaveEvent = self.leaveFrame

        self.show_pb.setVisible(False)

        pixmapi = getattr(QStyle, "SP_ArrowUp")
        icon = self.style().standardIcon(pixmapi)
        self.show_pb.setIcon(icon)


        self.resized.connect(self.resizeWindow)
        self.resized.emit()

    def resizeEvent(self, event):
        self.resized.emit()
        return super(Ui, self).resizeEvent(event)

    def resizeWindow(self):
        self.statusBar.setMaximumSize(self.width(), 125)
        self.statusBar.resize(16777215, 125)

        if self.statusBar.isVisible():
            bHW_height = self.statusBar.y()-70
            cDW_height = bHW_height-50
        else:
            bHW_height = self.height()-70
            cDW_height = bHW_height-50

        self.buttonsHorizontalWidget.move(20, bHW_height)


        #self.createDirWidget.move(20, cDW_height)
        table_height = self.buttonsHorizontalWidget.y()-40
        self.frame.move(20, self.buttonsHorizontalWidget.y()-30)

        if self.to_create_dir:
            table_height-=35


        """if not self.to_create_dir:
            if self.label.isVisible():
                for v in (self.label, self.new_dir, self.create_button, self.cancel_new_dir_button):
                    v.setVisible(False)
        else:
            self.frame.move(20, table_height)
            if not self.label.isVisible():
                for v in (self.label, self.new_dir, self.create_button, self.cancel_new_dir_button):
                    v.setVisible(True)"""
        self.table.resize(self.width()-40, table_height)


        self.back_button.move(self.width()-20-self.back_button.width(), self.table.y()+self.table.height()+10)
        self.mainProgressWidget.setMaximumWidth(self.progressArea.width())

        self.statusbar_raise_frame.resize(self.width()-(self.delete_button.x()+self.delete_button.width()+ self.width()-self.back_button.x())-40,30)
        self.statusbar_raise_frame.move(self.delete_button.x()+self.delete_button.width()+30, self.height()-55)
        self.show_pb.move(int(self.width()/2-290), 10)

    def openSettings(self):
        settings = Settings(self.username, self, self.settings)
        settings.show()
        settings.exec_()

    def backEvent(self):
        self.current_path = self.current_path.parent
        if not self.current_path.parent:
            self.path_status.setText("")
        else:
            self.path_status.setText(self.current_path.getFullPath())
        self.loadFilesToGui()

    def changedRowEvent(self):
        try:
            if self.table.selectedItems()[1].text()=="DIR":
                self.download_button.setText("Open")
            else:
                self.download_button.setText("Download")
        except IndexError:
            pass

    def openPreferencesWindow(self):
        self.preferences = Preferences(self)
        self.preferences.show()

    def createDefaultSettings(self):
        with open(".settings","w") as f:
            settings = {}
            settings["download-folder"] = "%s"%os.path.join(os.path.expanduser('~'), "Oprivstor Downloads")
            settings["temp-folder"] = "%s"%os.path.realpath(tempfile.gettempdir())
            f.write(json.dumps(settings))

    def readSettings(self):
        # check if style settings exists
        self.panel_status[0]="Reading Settings"
        if not os.path.exists(".settings"):
            self.createDefaultSettings()
        self.settings = json.loads(open(".settings","r").read())
        self.download_folder = self.settings["download-folder"]
        self.tmp_folder = self.settings["temp-folder"]

        if not os.path.exists("styles"):
            os.mkdir("styles")

        for v, style in ("Solarized", Preferences.solarized_style), ("Carbon", Preferences.carbon_style):
            if not os.path.exists(os.path.join("styles",v)):
                print("\n[-] Theme %s doesn't exist. Creating it..."%v)
                with open(os.path.join("styles",v), "w") as f:
                    f.write(json.dumps(style))


        if not os.path.exists(".styles"):
            print("\n[-] .styles doesn't exist. Creating it with default theme Solarized\n")
            try:
                with open(".styles","w") as f:
                    f.write("Solarized")
            except Exception as e:
                print("\n[!] Unable to create .styles file:",e,"\n")
            finally:
                self.styles = Preferences.solarized_style.copy()
        else:
            style = open(".styles","r").read().strip()
            if not os.path.exists(os.path.join("styles",style)):
                print("\n[-] Cannot find style: %s. Loading default: Solarized\n"%style)
                self.styles = Preferences.solarized_style
            else:
                try:
                    self.styles = json.loads(open(os.path.join("styles",style).strip(), "r").read())
                except json.decoder.JSONDecodeError:
                    print("Invalid Json Format of style: %s"%os.path.join("styles",style))

        for item in (self.download_folder, os.path.join(self.tmp_folder, "Oprivstor")):
            if not os.path.exists(item):
                try:
                    os.mkdir(item)
                except Exception as e:
                    print("\n[-] Unable to create folder:%s.\nException: %s\nExiting..."%(item, e))
                    sys.exit()


    def __init__(self):
        super(Ui, self).__init__()

        self.load_files.connect(self.loadFilesToGui)
        self.rename_signal.connect(self.renameItem)
        #self.show_error.connect(self.showError)


        self.to_create_dir=False
        self.authenticated=0
        self.progressWidgets = []
        self.loadUi()

        self.server, self.server_port = sys.argv[1:3]


        self.active_jobs=0
        self.jobs={}
        self.job_id=0
        self.current_job=[self.job_id]

        self.loadFilesThread = LoadFilesToGui()

        self.progresses={}

        self.cutted={}
        self.moveItems=False
        self.loaded=False

        self.current_path = Node()

        self.panel_status=["", ""]

        self.styles = None
        self.preloadActions()


        self.window = Panel(self, self.panel_status)
        self.window.exec_()

        if not self.authenticated: # not authenticated. exited
            self.close()
            sys.exit()

        self.setStyles()


        self.show()
        self.resized.emit()

        self.parseAndListFiles()


        self.error.setStyleSheet("color: red")
        self.opacity_effect = QGraphicsOpacityEffect()
        self.error.setGraphicsEffect(self.opacity_effect)


    def enterFrame(self, event):
        self.show_pb.setVisible(True)

    def leaveFrame(self, event):
        pos = self.mapFromGlobal(QCursor.pos())
        if pos.y()<self.height()-30 or pos.x()<self.statusbar_raise_frame.x() or pos.x()>self.statusbar_raise_frame.x()+self.statusbar_raise_frame.width():
            self.show_pb.setVisible(False)

    def preloadActions(self, thread=False):
        if not thread:
            a=threading.Thread(target=self.preloadActions, args=(True,))
            a.daemon=True
            a.start()
            return

        self.readSettings()
        time.sleep(.5)
        self.warmCryptographyEngine()
        time.sleep(.5)
        self.exchangeKeysWithServer()

    def parseAndListFiles(self, thread=False):
        if not thread:
            a=threading.Thread(target=self.parseAndListFiles, args=(True,))
            a.daemon=True
            a.start()
            return
        self.getFiles()
        self.load_files.emit()

    def showError(self, error):
        self.showErrorThread = showError()
        self.showErrorThread.setError(error)
        self.showErrorThread.update.connect(self.showErrorMessage)
        self.showErrorThread.start()

    def showErrorMessage(self, error, opacity):
        self.error.setText(error)
        self.opacity_effect.setOpacity(opacity)

    def loadFilesLoop(self, thread=False):
        if not thread:
            a=threading.Thread(target=self.loadFilesLoop, args=(True,))
            a.daeon=True
            a.start()
            return

        colors = ["background-color: rgb(109, 74, 255);border-radius: 5;border: 1px solid rgb(109, 74, 255);","background-color: rgb(22, 20, 28);border-radius: 5;border: 1px solid rgb(22,20,28);","background-color: rgb(22, 20, 28);border-radius: 5;border: 1px solid rgb(22,20,28);"]
        buttons=(self.b0, self.b1, self.b2)
        [v.setStyleSheet(colors[1]) for v in buttons]

        for v in buttons:
            v.setVisible(True)
            self.load_frame.setVisible(True)

        while not self.loaded:
            for i in range(len(buttons)):
                buttons[i].setStyleSheet(colors[i])
            colors.insert(0, colors.pop())
            time.sleep(0.2)
        for v in buttons:
            v.setVisible(False)
            self.load_frame.setVisible(False)

    def createEncryptedPassword(self, password, master_passwd=None):
        hash = self.cr.createHash(password).encode()

        salt = os.urandom(16)
        iv = os.urandom(16)
        hashed = hash_password_raw(hash_len=16, password=password.encode(), salt=salt).hex()

        if not master_passwd:
            master_passwd = os.urandom(32)

        encrypted_master_passwd, tag = self.cr.encryptAES_GCM(hashed, iv, master_passwd)

        enc_info = [salt, encrypted_master_passwd, iv, tag, hash]
        enc_info = [v.hex() for v in enc_info]




        return "\n".join(enc_info), master_passwd

    def connectToServer(self):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((self.server,int(self.server_port)))
            s.close()
            return True
        except Exception as e:
            print(e)
            return False

    def LoginPanel(self, username, password, action):
        try:
            command = ("%s %s %s"%(action.upper().encode().hex(),username.encode().hex(),password.encode().hex())).encode()
            enc_msg=self.cr.createMessage(command, self.server_public_key)
            self.s.send(enc_msg)
            response = self.cr.decryptMessage(self.getResponseFromServer(),self.private_key).decode()


            if response[0]=='0':
                self.username = username
                self.password = password
                self.authenticated=True
            else:
                return response[1:]

            if action=="SIGNUP":
                message, master_passwd = self.createEncryptedPassword(self.password)

                self.s.send(self.cr.createMessage(message.encode(), self.server_public_key))

                res = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key).decode()
                if res=="0":
                    self.master_passwd = master_passwd
                    return self.authenticated
                return res[1:]

            if self.authenticated:
                self.s.send(self.cr.createMessage(b"0", self.server_public_key))
                enc_info = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key)

                salt = enc_info[0:16]
                master_passwd = enc_info[16:48]
                iv = enc_info[48:64]
                tag = enc_info[64:80]


                hash = hash_password_raw(hash_len=16, password=password.encode(), salt=salt).hex()
                self.master_passwd = self.cr.decryptAES_GCM(hash,iv,tag,master_passwd)

            return self.authenticated

        except KeyboardInterrupt:
            sys.exit()

    def warmCryptographyEngine(self):
        self.panel_status[0]="Creating Cryptographic Keys"
        self.cr = Cryptography()
        self.private_key,public_key, self.public_pem = self.cr.createRSAKeysWithPem()

    def exchangeKeysWithServer(self, main_connection=True):
        self.panel_status[0]="Connecting to Server"

        while True:
            try:
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect((self.server,int(self.server_port)))
                break
            except Exception as e:
                for i in range(11):
                    self.panel_status[1]="Connection with server failed. Retrying in %d secs."%(10-i)
                    time.sleep(1)

        time.sleep(.5)

        self.panel_status[0]="Exchanging Cryptographic Keys."

        s.send(("EXCHANGE %s"%('' if main_connection else "0")).encode())

        server_public_key = self.cr.getPublicFromPEM(self.getResponseFromServer(socket=s, exchange_mode=True))

        s.send(self.cr.createMessage(self.public_pem, server_public_key))


        if main_connection:
            self.s=s
            self.server_public_key=server_public_key

            response = self.cr.decryptMessage(self.getResponseFromServer(), self.private_key).decode().split()

            self.greeting=' '.join(response[:-1])
            self.panel_status[0]=None
            self.command_uuid = response[-1]
            return self.command_uuid
        else:
            s.recv(1024)
            return s, server_public_key

    def getResponseFromServer(self, socket=False, exchange_mode=False, items=None):
        if not socket: socket=self.s
        if not exchange_mode:
            r=socket.recv(1024*1024)
            size = self.cr.decryptMessage(bytes().fromhex(r.decode()), self.private_key)
            to_send = self.cr.createMessage(b"0", self.server_public_key)
        else:
            size = bytes().fromhex(socket.recv(1024).decode())
            to_send=b"0"
        if size==False:
            print("Failed to validate message. For security purposes connection is shut down")
            socket.close()

            self.close()

            return False

        socket.send(to_send)
        size = int(size.decode())
        total=0
        data=b""
        while total<size:
            buffer = socket.recv(1024*1024)
            total+=len(buffer)
            data+=buffer

        return data

    """def getResponseFromServer(self, socket=False, exchange_mode=False, verification=False):
        if not socket: socket = self.s
        print("socket is:",socket, exchange_mode)
        if not exchange_mode:
            return getResponse(socket, self.cr, server_public_key=self.server_public_key, private_key=self.private_key, exchange_mode=False, verification)
        else:
            return getResponse(socket, None, None, None, True, verification=False)"""

    def changePassword(self, password):
        enc_info, _ = self.createEncryptedPassword(password, self.master_passwd)

        message = "%s %s CHPASSWD %s"%(self.command_uuid, self.username, enc_info)

        s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

        s.send(self.cr.createMessage(message.encode(), server_public_key))

        # result will start with 1 if command uuid is wrong or its right but server already finds the path or an exception happens
        result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode() # verification of uuid

        s.close()
        if result[0]=="1":
            print(result[1:])
            return

    def getFiles(self, node_path=None):
        if not node_path:
            path = self.current_path.getFullPath()
        else:
            path = node_path.getFullPath()
        command = ("LS %s"%(path.encode().hex())).encode()
        enc_msg=self.cr.createMessage(command, self.server_public_key)
        self.s.send(enc_msg)
        response = self.cr.decryptMessage(self.getResponseFromServer(self.s),self.private_key)
        if not response:
            self.current_path.visited=True
            return
        if response[0]=="1":
            print("\n[Error]:",response[1:])
            return

        data=response.decode().split()
        while data:
            item=[]
            for j in range(6):
                item.append(bytes().fromhex(data.pop(0)).decode().strip())


            if node_path:
                node = Node(node_path, item)
                node_path.files.append(node)
            else:
                node = Node(self.current_path, item)
                self.current_path.files.append(node)

        self.current_path.visited=True

    def getTypeButton(self, type):
        item=QPushButton()
        item.setText(type)
        item.setStyleSheet("color: white ;background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0.01, y2:0, stop:1 rgba(255, 255, 255, 0));border: none;")

        if type=="DIR":
            name="SP_DirIcon"
        elif type=="FILE":
            name="SP_FileIcon"
        elif type=="DIROPEN":
            name="SP_DirOpenIcon"
        pixmapi = getattr(QStyle, name)
        icon = self.style().standardIcon(pixmapi)
        item.setIcon(icon)
        return item

    def loadFilesToGui(self):
        self.loaded=False
        if self.current_path.parent==None:
            self.back_button.setVisible(False)
        else:
            self.back_button.setVisible(True)

        self.loadFilesLoop()

        self.loadFilesThread.exit()

        self.loadFilesThread = LoadFilesToGui()
        self.loadFilesThread.setFiles(self.current_path.files)
        self.loadFilesThread.setStyle(self.style)
        self.loadFilesThread.add_row.connect(self.addItemToTable)
        self.loadFilesThread.start()

    def addItemToTable(self, item_info):
        if not item_info:
            self.loaded=True
            return
        elif item_info[0]=="0":
            self.table.setRowCount(0)
            return

        row = self.table.rowCount()
        self.table.insertRow(row)

        for j in range(6):
            if j==1:
                item = self.getTypeButton(item_info[j])
                self.table.setCellWidget(row, j, item)
            else:
                item=QTableWidgetItem(item_info[j])
                #item.setData(Qt.ForegroundRole, QVariant(QColor(self.styles["table_items"])) );
                self.table.setItem(row, j, item)

    def deleteFile(self, id):
        info = [v.text() for v in self.table.selectedItems()[0:2]]
        if not info:return

        result = QMessageBox.warning(self, 'Confirm Deletion', "Are you sure you want to delete %s"%info[0], buttons=QMessageBox.Yes | QMessageBox.Cancel)
        if result==QMessageBox.Cancel:
            return

        if not info: return

        file, type = info
        full_path = os.path.join(self.current_path.getFullPath(), file)

        encoded_filename=full_path.encode().hex()
        message = "%s %s DELETE %s"%(self.command_uuid, self.username, encoded_filename)

        try:
            s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

            s.send(self.cr.createMessage(message.encode(), server_public_key))

            result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

            s.close()
        except Exception as e:
            print(e)
            self.showError("Command failed. Lost connection with server.")
            return


        if result[0]=="1":
            self.showError("Action Failed. [Server]: "+result[1:])
        else:
            self.table.removeRow(self.table.selectedItems()[0].row())
            i=0
            for i in range(len(self.current_path.files)):
                if self.current_path.files[i].name==file:
                    self.current_path.files.pop(i)
                    break
                i+=1
        return

    def renameItem(self, new_name):
        item = self.table.selectedItems()[0]
        item.setText(new_name)

    def executeRenameItem(self, parent, name, new_name, status, thread=False):
        if not thread:
            a=threading.Thread(target=self.executeRenameItem, args=(parent, name, new_name, status, True,))
            a.daemon=True
            a.start()
            return

        full_path=os.path.join(parent.getFullPath(), name)
        encoded_filename=full_path.encode().hex()
        encoded_new_filename = new_name.encode().hex()
        message = "%s %s RENAME %s %s"%(self.command_uuid, self.username, encoded_filename,encoded_new_filename)

        try:
            s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

            s.send(self.cr.createMessage(message.encode(), server_public_key))

            result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode()

            s.close()
        except Exception as e:
            print(e)
            self.showError("Command failed. Lost connection with server.")
            return


        if result[0]=="1":
            print(result[1:])
            self.showError("Action Failed. [Server]: "+result[1:])
            status[0]=2
        else:
            self.rename_signal.emit(new_name)
            status[0]=1

            """
            change parent of all items in memory
            """
            for file in self.current_path.files:
                if file.name == os.path.basename(name):
                    file.name = new_name
                    self.setEnabled(True)


    def openRenameWindow(self, item):
        #item = self.table.selectedItems()[0]
        #self.table.openPersistentEditor(item)
        #return
        self.setEnabled(False)
        self.rename_window=Rename(self, self.current_path, item)
        self.rename_window.rename_signal.connect(self.renameItem)

    def moveItem(self, item, destination, destination_node):
        #print("Move: ",item," To: ",destination)
        #return
        # server doesnt have the command yet

        message = "%s %s MOVE %s %s"%(self.command_uuid, self.username, item.encode().hex(), destination.encode().hex())

        s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

        s.send(self.cr.createMessage(message.encode(), server_public_key))

        # result will start with 1 if command uuid is wrong or its right but server already finds the path or an exception happens
        result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode() # verification of uuid

        s.close()
        if result[0]=="1":
            print(result[1:])
        else:
            item = self.table.selectedItems()
            for i in range(len(self.current_path.files)):
                if self.current_path.files[i].name==item[0].text():
                    destination_node.files.append(self.current_path.files[i])
                    self.current_path.files[i].parent=destination_node
                    self.current_path.files.pop(i)
                    break

            self.table.removeRow(item[0].row())
            self.table.clearSelection()

    def openMoveItemsWindow(self, item):
        self.setVisible(False)
        self.move_items_window = moveItems(self.current_path, os.path.join("/" if not self.path_status.text() else self.path_status.text(),item), self)

    def openItem(self):
        info = [v.text() for v in self.table.selectedItems()]

        if not info:return

        if info[1]=="-": # not size. we cant get type because we get selected ITEMS and type if a widget
            i=0
            """
            Error here when back button is hit multiple times and table has loaded items from different paths
            """
            while not self.current_path.files[i].name == info[0]:
                i+=1
            item = self.current_path.files[i]
            self.current_path = item
            self.path_status.setText(item.getFullPath())
            if not self.current_path.visited:
                self.getFiles()
            self.loadFilesToGui()
            return
        else:
            info.insert(0, self.current_path.getFullPath())
            self.downloadFile(info)

    def executeActionPreload(self, info, action):
        if action=="Upload":
            full_path=os.path.join(info[0].name, info[1])
        else:
            full_path=os.path.join(info[0], info[1])

        if full_path in progressThread.locked:
            return None, None
        new_progress = self.addProgressWidget(info[1], action)
        id=self.job_id
        self.job_id+=1
        self.active_jobs+=1
        self.jobs[id] = new_progress

        extra = [self.command_uuid, self.username, self.server_public_key, self.settings, self.server, self.server_port, self.master_passwd]
        return id, extra

    def downloadFile(self, info):
        id, extra = self.executeActionPreload(info, "Download")
        if id is None:
            self.showError("Failed to download. Already downloading it.")
            return
        download_progress = progressThread(id, info, extra, "download", self.current_job)
        download_progress.start()
        download_progress.progress_update.connect(self.updateProgressInfo)


        self.progresses[id]=download_progress # to avoid garbage collection

    def itemExists(self, item):
        for v in self.current_path.files:
            if v.name == item: return True
        return False

    def uploadFile(self, response):
        if not self.sender().objectName() not in ("action_upload_file", "upload_button"):
            file = self.getFile()
            if not file: return

            self.upload_window = UploadFileUI(self.current_path.getFullPath(), file, self.itemExists(os.path.basename(file)), self.current_path.files, self.styles)
            self.upload_window.upload_signal.connect(self.uploadFile)
            self.upload_window.show()


        else:
            new_name=None
            overwrite=False
            compress=False
            """
            response:
            [False]: cancel
            [True, file, new_name, compress]: ok
            [file, new_name, True/False, compress]: overwrite or write to new name
                if overwrite is False then new_name will be used
                else if overwrite is True will will do nothing
            """
            if response[0]==False:
                return
            elif response[0]==True:
                file = response[1]
                new_name = response[2]
                compress = response[3]
            else:
                file = response[0]
                new_name = response[1]
                overwrite = response[2]
                compress = response[3]
            response.clear()

            info = [self.current_path, file, os.path.getsize(file), new_name, compress]

            id, extra = self.executeActionPreload(info, "Upload")
            if id is None:
                self.showError("Failed to upload. Already uploading it.")
                return

            upload_progress = progressThread(id, info, extra, "upload", self.current_job)
            upload_progress.start()
            upload_progress.progress_update.connect(self.updateProgressInfo)

            self.progresses[id]=upload_progress # to avoid garbage collection

    def getFile(self):
        fd = FileDialog()
        return fd.getResult()

    def getPath(self):
        fd = FileDialog(folder=True)
        return fd.getResult()

    def newDirChangedEvent(self):
        value = self.new_dir.text()
        if not value: return

        found = any([v.name==value for v in self.current_path.files])
        if found:
            self.new_dir.setStyleSheet("color: rgb(224, 27, 36)")
            self.create_button.setEnabled(False)
        else:
            self.new_dir.setStyleSheet("color: rgb(1, 208, 12)")
            self.create_button.setEnabled(True)

    def createDirAction(self):
        if self.to_create_dir:
            self.cancelCreateDir()
            return
        self.to_create_dir=True

        for v in (self.label, self.new_dir, self.create_button, self.cancel_new_dir_button):
            v.setVisible(True)
            self.resized.emit()

    def createButtonClicked(self):
        self.createDirectory(self.new_dir.text())

    def cancelCreateDir(self):
        for v in (self.label, self.new_dir, self.create_button, self.cancel_new_dir_button):
            v.setVisible(False)
        self.create_button.setEnabled(False)
        self.new_dir.setText("")
        self.to_create_dir=False
        self.resized.emit()

    def createDirectory(self, dir):
        encoded_filename=(os.path.join(self.current_path.getFullPath(), dir)).encode().hex()
        message = "%s %s MKDIR %s"%(self.command_uuid, self.username, encoded_filename)

        s, server_public_key = self.exchangeKeysWithServer(main_connection=False)

        s.send(self.cr.createMessage(message.encode(), server_public_key))

        # result will start with 1 if command uuid is wrong or its right but server already finds the path or an exception happens
        result = self.cr.decryptMessage(s.recv(1024), self.private_key).decode() # verification of uuid

        s.close()
        if result[0]=="1":
            print(result[1:])
        else:

            type, size, mod, up, compressed = result.split("\n")
            row=self.table.rowCount()
            self.table.insertRow(row)
            j=0
            for v in (dir, type, size, mod, up, compressed):
                if j==1:
                    item = self.getTypeButton(type)
                    self.table.setCellWidget(row, j, item)
                else:
                    item = QTableWidgetItem(v)
                    self.table.setItem(row, j, item)
                j+=1
            node = Node(self.current_path, (dir, type, size, mod, up, compressed))
            self.current_path.files.append(node)
        self.cancelCreateDir()
        return

    def showItems(self, type):
        self.table.setRowCount(0)
        i=0
        for file in self.current_path.files:
            if file.type == type:
                self.table.insertRow(i)
                j=0
                for v in file.getInfo():
                    item = QTableWidgetItem(v)
                    self.table.setItem(i,j, item)
                    j+=1
                i+=1

    def searchFiles(self, value):
        self.table.setRowCount(0)
        i=0
        for file in self.current_path.files:
            if value.lower() in file.name.lower():
                if self.actionShow_Directories_Only.isChecked():
                    if file.type!="DIR":
                        continue
                elif self.actionShow_Files_Only.isChecked():
                    if file.type!="FILE":
                        continue
                self.table.insertRow(i)
                j=0
                for col in file.getInfo():
                    item = QTableWidgetItem(col)
                    self.table.setItem(i,j, item)
                    j+=1

    def addProgressWidget(self, file, action):

        widget = QWidget()
        self.progressWidgets.append(widget)

        layout = QHBoxLayout()


        ac = QLabel()
        ac.setText(action)
        ac.adjustSize()
        ac.setFixedSize(ac.width(), 25)

        status = QLabel()
        status.setText("Decompressing...")
        status.adjustSize()
        status.setFixedSize(status.width(), 25)
        status.setText("")

        progressBar = QProgressBar()
        progressBar.setValue(0)
        progressBar.setFixedSize(int(950*0.40), 25)
        progressBar.setAlignment(Qt.AlignCenter)

        file_label = QLineEdit()
        file_label.setReadOnly(True)
        file_label.setText(file+": ")
        file_label.adjustSize()
        file_label.setFixedSize(950-(progressBar.width()+status.width()+ac.width())-int(950*0.1), 25)
        file_label.setToolTip(file)
        file_label.setCursorPosition(0)

        layout.addWidget(ac)
        layout.addWidget(file_label)
        layout.addWidget(progressBar)
        layout.addWidget(status)

        for v in (progressBar, ac, file_label, status):
            v.setStyleSheet("color: %s"%self.styles["status_bar_items"])

        progressBar.setStyleSheet("selection-background-color: %s"%self.styles["progressbar"])

        widget.setLayout(layout)
        widget.resize(self.width(), 30)

        self.mainProgressWidget.setMaximumWidth(self.progressArea.width())

        self.vlayout.insertWidget(0,widget)
        self.vlayout.addItem(QSpacerItem(self.width()-20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))




        return [progressBar, status, widget]

    def toggleProgressArea(self, value):
        """
        Value:
        True:  to show  status bar
        False: to hide progress bar
        1    : to set action checked and then continue the same function
        """
        if value==1:
            self.actionProgress_Status.setChecked(True)
        if not value:
            self.statusBar.hide()
            self.resized.emit()
            self.show_pb.setVisible(False)
        else:
            self.statusBar.show()
            self.resized.emit()

    def openFile(self, path):
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def updateProgressInfo(self, id, value, text, dest):
        bar, status, _ = self.jobs[id]
        if value==-1: # removing object so garbage collection will delete it
            self.current_job[0]+=1
            if dest:
                button = self.getTypeButton("DIROPEN")
                button.setText("")
                button.setStyleSheet("QPushButton{border: 1px;background-color: %s;};\nQPushButton:hover {background-color:rgb(109,74,255);}"%self.styles["main_background"])
                button.clicked.connect(lambda: self.openFile(dest[0]))
                button.setFixedSize(30,30)




            if text:
                """
                When value == -1, update or download is done
                but set a value for text only on upload
                That way we can insert a new node passing the metadata of
                the new file via text variable
                We also need the parent node from uploaded file.
                We passed it to upload process at the beggining but
                we need it now in case user enters a different path.
                Meaning we cant use self.current_path

                the parent node will be inside dest.
                when Download dest has the location for the downloaded file
                But now we can use it for the parent node

                So now we first we are searching if file already exists in parent node
                If it does we will call updateInfo to update it
                And then if we are still on parent folder we will change the content of the table
                to match the new record

                If uploaded file doesnt already exist in parent node then we will
                create a new node and at last check if we are still on parent node
                If yes we will a new row. Else we will do nothing and load
                the content when user enters that particular folder.

                Also dest is a list because it might be either a string or Node()
                Signal will not accept both but it will accept a list ;)
                A list where for download first item is the file path link
                and for upload the parent node
                """
                button = QPushButton()
                button.setFixedSize(30,30)
                button.setStyleSheet("border: none")
                text=text.split("\n")

                parent_node = dest[0]

                found=False
                for node in parent_node.files:
                    if node.name==text[0]:
                        found=True
                        node.updateInfo(text[1:])
                        break

                if found:
                    if parent_node==self.current_path:
                        for i in range(self.table.rowCount()):
                            if self.table.item(i,0).text()==text[0]:
                                for j in range(1,6):
                                    if j==1:
                                        self.table.cellWidget(i,j).setText(text[j])
                                    else:
                                        self.table.item(i,j).setText(text[j])
                                break
                else:
                    node = Node(self.current_path, text)
                    parent_node.files.append(node)

                    if parent_node==self.current_path:
                        row=self.table.rowCount()
                        self.table.insertRow(row)
                        j=0
                        for v in text:
                            if j==1:
                                item = self.getTypeButton(v)
                                self.table.setCellWidget(row, j, item)
                            else:
                                item  = QTableWidgetItem(v)
                                self.table.setItem(row,j, item)
                            j+=1

            for v in self.jobs:
                if v==id:
                    self.jobs[v][-1].layout().addWidget(button)
                    bar.setFormat('Completed')
                    return

            time.sleep(1)
            self.progresses.pop(id)
            return

        bar.setValue(value)
        if text:
            status.setText(text)
            status.adjustSize()

    def clearCompletedProgresses(self):
        i=0
        while i < len(self.progressWidgets):
            widget = self.progressWidgets[i]
            layout = widget.layout()
            if layout.itemAt(3).widget().text()=="Done":
                widget.setParent(None)
                self.progressWidgets.pop(i)
                i-=1
            i+=1

class Node():
    def __init__(self, parent=None, item=None):
        self.parent = parent
        if item:
            self.name, self.type, self.size, self.mod_date, self.up_date, self.compressed = item
            if self.type=="FILE":
                self.files = None
            else:
                self.files=[]
                self.visited=False
        else:
            self.name="/"
            self.files = []
            self.visited=True

    def getFullPath(self):
        if not self.parent: return "/"
        return os.path.join(self.parent.getFullPath(), self.name)

    def getInfo(self):
        return [self.name, self.type, self.size, self.mod_date, self.up_date, self.compressed]

    def updateInfo(self, info):
        self.type, self.size, self.mod_date, self.up_date, self.compressed = info

class Panel(QDialog):
    authenticated=False
    draw_button = pyqtSignal(QPushButton, str, QPushButton, str)
    countdown = pyqtSignal(int)
    def __init__(self, client, status):
        super(Panel, self).__init__()

        while not client.styles:
            time.sleep(0.1)

        uic.loadUi(os.path.join("ui","oprivstor_login.ui"), self)
        self.go_button.clicked.connect(self.validateCredentials)
        self.cancel_button.clicked.connect(self.Exit)
        self.login_button.clicked.connect(lambda: self.changeHeader("Oprivstor Login", "LOGIN"))
        self.signup_button.clicked.connect(lambda: self.changeHeader("Oprivstor SignUp", "SIGNUP"))
        self.verify_label.setVisible(False)
        self.password_verify.setVisible(False)

        self.status = status


        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        self.draw_button.connect(self.drawButton)
        self.countdown.connect(self.updateError)

        self.ready=False
        self.client=client
        self.connected_to_server = False
        self.retry_sec_on_error = 10
        self.exit = False

        self.changeHeader("Oprivstor Login", "LOGIN")

        #self.server_message.setPlainText(greeting)

        self.error_label.setText("")

        self.setStyleSheet("background-color: %s; color:%s"%(self.client.styles["main_background"], self.client.styles["main_color"]))

        #self.frame.setStyleSheet("background-color: %s"%self.client.styles["main_background"])

        #self.setStyleSheet("background-color: %s"%self.client.styles["secondary_background"])

        self.load_frame.setStyleSheet("background-color: %s"%self.client.styles["main_background"])

        self.line_2.setStyleSheet("color: %s"%self.client.styles["line"])
        self.line_3.setStyleSheet("color: %s"%self.client.styles["line"])

        style = """
        QPushButton:hover {
            color:%s;
            background-color:%s;
        }
        QPushButton {
            color: %s;
            background-color: %s;
            border: 1px solid %s
        }
        """%(self.client.styles["button_color"], self.client.styles["button_background_hover"],self.client.styles["button_color"], self.client.styles["secondary_background"],self.client.styles["button_color"])
        for v in (self.cancel_button, self.go_button):
            v.setStyleSheet(style)

        self.error_label.setStyleSheet("color: %s;"%self.client.styles["error"])
        #self.login_button.setStyleSheet("background-color: %s;"%self.client.styles["button_background_hover"])
        #self.signup_button.setStyleSheet("background-color: %s;"%self.client.styles["button_background_hover"])

        font = QFont("sans-serif", 20)
        font.setBold(True)
        self.title_label.setFont(font)

        for v in (self.username, self.password, self.name_label, self.password_label, self.password_verify, self.go_button, self.cancel_button):
            font = QFont("sans-serif", 10)
            v.setFont(font)




        #self.error_label.setVisible(False)

        self.show()
        self.loop()


    def updateError(self, i):
        self.error_label.setText("Connection Failed. Retrying in %d sec."%(self.retry_sec_on_error-i))


    def drawButton(self, button, style, button2, style2):
        button.setStyleSheet(style)
        button2.setStyleSheet(style2)


    def loop(self, a=0):
        if not a:
            a=threading.Thread(target=self.loop, args=(1,))
            a.daeon=True
            a.start()
            return

        colors = ["background-color: %s ;border-radius: 5;border: 1px solid %s;"%(self.client.styles["circle"],self.client.styles["circle"]),"background-color: %s;border-radius: 5;border: 1px solid %s;"%(self.client.styles["circle_background"],self.client.styles["circle_background"]),"background-color: %s;border-radius: 5;border: 1px solid %s;"%(self.client.styles["circle_background"],self.client.styles["circle_background"])]
        buttons=(self.b0, self.b1, self.b2)
        [v.setStyleSheet(colors[1]) for v in buttons]

        for v in buttons:
            v.setVisible(True)

        i=0
        status = self.status[0]
        error = self.status[1]
        self.label.setText(status)
        while not self.connected_to_server and not self.exit:
            if self.status[0] is None: break
            if status!=self.status[0]:
                status=self.status[0]
                self.label.setText(status)
            if error!=self.status[1]:
                error=self.status[1]
                self.error_label.setText(error)

            self.draw_button.emit(buttons[i], colors[0], buttons[i-1],colors[1])
            time.sleep(0.2)
            i+=1
            if i==3: i=0
        for v in buttons:
            v.setVisible(False)

        self.load_frame.setVisible(False)
        self.username.setFocus(True)


    def changeHeader(self, value, action):
        self.title_label.setText(value)
        self.action = action

    def closeEvent(self, event):
        self.exit=True
        event.accept()

    def Exit(self):
        self.close()

    def validateCredentials(self):
        username = self.username.text()
        if not username:
            QMessageBox.critical(self, 'Action Failed', "Username can't be null", buttons=QMessageBox.Ok,)

        elif not self.password.text():
            QMessageBox.critical(self, 'Action Failed', "Password can't be null", buttons=QMessageBox.Ok,)

        else:
            if self.action == "SIGNUP":
                if self.password.text()!=self.password_verify.text():
                    QMessageBox.critical(self, 'Action Failed', "Password doesn't match", buttons=QMessageBox.Ok,)
                    return
            result = self.client.LoginPanel(username, self.password.text(), self.action)
            if result==True:
                self.Exit()
            else:
                QMessageBox.critical(self, 'Action Failed', result, buttons=QMessageBox.Ok,)


if len(sys.argv[1:])!=2:
    print("Pprivstor\n\nUsage: python3 %s <server> <port>\n"%sys.argv[0])
    sys.exit()
else:
    try:
        int(sys.argv[2])
    except ValueError:
        print("\n[!] Invalid Port\n")
        sys.exit()
app = QApplication(sys.argv)
window = Ui()
app.exec_()
