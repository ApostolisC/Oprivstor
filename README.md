<h2>Oprivstor Project Overview</h2>

**Introduction**

This particular project is a client-server application that allows the user to upload and download files. The transmission of the data is carried out using hybrid cryptography with message authentication techniques, while the encryption of the files itself is carried out using symmetric cryptography with zero server involvement. Thus, the security of communication is ensured, as well as the confidentiality of the files themselves.
Finally, the user can specify  lossless compression to be applied before encrypting and sending the file to the server.

**Installation**
1. Clone the repository from GitHub: `git clone https://github.com/ApostolisC/Oprivstor.git`
2. Install the required dependencies using `pip install -r requirements.txt`
3. Run the server script: `python server.py <host> <port>`
4. Run the client script: `python client.py <server> <port>`

**Usage**

1. Start the server by running the `server.py` script.
2. Start the client by running the `client.py` script.
3. On the client-side, enter your account details to login (or signup) to the server.
4. Once logged in, you can upload and download files using the respective options provided by the client GUI.

**Important Features**

* Secure communication between client and server using hybrid encryption.
* Client-side encryption and decryption of files.
* Client-side compression of files before uploading.

**Conclusion**

That's it! This README file should provide you with all the necessary information to get started with this project. If you have any questions or issues, please feel free to contact me at contact.oprivstor@protonmail.ch. 
Thank you for using my data storage server!
