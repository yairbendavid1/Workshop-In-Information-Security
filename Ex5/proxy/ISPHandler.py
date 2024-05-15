import socket
import re
from ExternalProxyHandler import ExternalProxyHandler

FAKE_PORT = 800
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world

class ISPHandler(ExternalProxyHandler):
    def recv_info(self, sock):
        """ Receives information sent to the socket """
        total = ''
        size = 512
        
        while True:
            current = sock.recv(size)
            total += current.decode()
            if len(current) < size:
                break
            
        return total
    

    def remove_lines_with_prefix(self, text):
        """
        This function takes a text string and removes any line that starts with the prefix "LINE" (case-insensitive).
        It returns the modified text.
        """
        lines = text.splitlines()
        print("Lines: \n", lines)
        modified_lines = [line for line in lines if not line.startswith("X-WCPAY-PLATFORM-CHECKOUT-USER:")]

        return "\n".join(modified_lines)


    
    """ Represents HTTP proxy connection """

    def filter_packet(self, message):
        """ Enforces the content type """
        
        # Extract header
        separator = '\r\n\r\n'  # indicates end of HTTP header
        # header_loc = message.index(separator)
        # header = message[0:header_loc]
        header = message

        # Check if should block
        content_type = re.findall('Content-Type: (\S+)', header)
        print('Content type: {}'.format(content_type)) # debug

        return False if content_type and (content_type[0] in ['text/csv', 'application/zip']) else True


    

    def perform_client_connection(self):
        print("\nPerforming client connection")
        while self.is_alive() and not self.done:
            request = self.recv_info(self.csocket)
            if request:
                print("\nRequest Recieved: \n", request)
                # Remove lines with prefix "X-WCPAY-PLATFORM-CHECKOUT-USER:"
                request = self.remove_lines_with_prefix(request)
                print("\nRequest Sent: \n", request)
                self.ssocket.sendall(request.encode())
            else:
                self.done = True


    def perform_server_connection(self):
        #print("Performing server connection")
        while not self.done:
            response = self.recv_info(self.ssocket)
            if response:
                self.csocket.sendall(response.encode())
            else:
                self.done = True



if __name__ == "__main__":
    # Creating an HTTP proxy server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enabling reuse the socket without time limitation
    sock.bind((FW_OUT_LEG, FAKE_PORT))
    sock.listen(10)
    proxies = []
    print("\nStarting")

    while True:
        try:
            connection, addr = sock.accept()
        except KeyboardInterrupt:
            for proxy in proxies:
                proxy.done = True
            for proxy in proxies:
                proxy.join()
            break

        print("\nConnection accepted")
        proxy = ISPHandler(connection, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


    