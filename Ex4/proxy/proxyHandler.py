import threading
import socket
import struct
import sys
import subprocess
import os


class ProxyHandler(threading.Thread):
    """This class is a parent class for all the types of the proxies (HTTP, FTP, etc.)"""

    FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
    FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
    PATH_TO_PROXY_DEV = '/sys/class/fw/proxy/set_port'

    """
    @param conn: The socket with the client.
    @param adrr: The address list of the client, return by the accept() method of the socket.
    """
    def __init__(self, conn, adrr):
        super(ProxyHandler, self).__init__()
        self.csocket = conn # This is the socket with the client, used to send and receive data.
        self.ssocket = None # This is the socket with the server, used to send and receive data.
        self.cip = addr[0] # The client's IP address
        self.cport = addr[1] # The client's port.
        self.sip = None # The server's IP address.
        self.sport = None # The server's port.
        self.done = False
        self.client_connection = None
        self.server_connection = None


    def run(self):
        """
        When using the threading.Thread class, this method is called when the thread starts.
        This method will be called for every new connection we want to create a proxy for.
        It will be called when we call the start() method of the threading.Thread class.
        The function will apply the setup for the proxy connection, and communicate with both the server and client.
        """
        # We first need to do the basic setup for the proxy connection.
        # it will fill the missing fields in the class, and will send the port to the firewall.
        self.setup()

        # After the setup, we have the server's IP and port, and we can start the communication with the server.
        self.ssocket.connect((self.sip, self.sport))

        # We then start the client and server threads.
        # each of them will be responsible for the communication with the client and server respectively.
        # starting with the client thread:
        self.client_connection = threading.Thread(target=self.perform_client_connection)
        self.client_connection.start()

        # and then the server thread:
        self.server_connection = threading.Thread(target=self.perform_server_connection)
        self.server_connection.start()

        # After the threads are done, we need to close the sockets.
        self.client_connection.join()
        self.server_connection.join()
        self.csocket.close()
        self.ssocket.close()



    # This function is responsible for communicating with the client.
    # This is an "abstract" method that should be implemented by the child classes.
    
      
    def perform_client_connection(self):
        pass

    # This function is responsible for communicating with the server.
    # This is an "abstract" method that should be implemented by the child classes.
    
    
    def perform_server_connection(self):
        pass


    def setup(self):
        """
        This method is responsible for the basic setup of the proxy connection.
        It will fill the missing fields in the class, and will send the port to the firewall.
        """
        # We first need to find the server's IP and port.
        # Since the firewall connection device is originally designed to work with c code,
        # The methadology of sending the connection table from the Connection device will be different.
        # To overcome this, we will use the already created C program we used in the previous part to get the connection table.
        # We can do so by running "main show_conns" and parsing the stdout.
        
        # first, we need to find the path to the user program.
        user_path = os.path.dirname(os.path.abspath(__file__)) + '/../user/main'
        print('User path: {}'.format(user_path))
        user_arg = "show_conns" # The argument we will pass to the user program.
        
        
        # Running the user program with the "show_conns" argument.
        p = subprocess.run([user_path, user_arg], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True)
        connections = p.stdout.splitlines()[1:]

        # Parse the output and find the matching server IP and port.
        print('src: ', self.src)
        for connection in connections:
            client_ip, client_port, server_ip, server_port, next_dir, status = connection.split()
            if client_ip == self.cip and int(client_port) == self.cport:
                self.sip = server_ip
                self.sport = int(server_port)
        print('dst: ', self.dst)


        # Now we need to craeting connection with the server, and send our source port to the firewall.
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket
        # We need to bind the socket to a port, so we can send the port to the firewall.
        sock.bind((self.FW_OUT_LEG, 0)) 
        self.ssocket = sock

        # get the port we are using from the socket.
        proxy_addr = sock.getsockname()
        proxy_port = proxy_addr[1]

        # and now need to send the port to the firewall.
        # The format of the message we need to send is:
        # <client_ip><client_port><proxy_port>
        # where IP is 4 bytes and the others are 2 bytes.

        # We can use the struct library to pack the data.
        client_ip = socket.inet_aton(self.cip)
        client_port = self.cport
        pack = struct.pack('<HH', client_port, proxy_port) if sys.byteorder == 'little' else struct.pack('>HH', client_port, proxy_port)
        buf = client_ip + pack

        # and now we can write the data to the proxy device.
        with open(self.PATH_TO_PROXY_DEV, 'wb') as file:
            file.write(buf)
        
        

