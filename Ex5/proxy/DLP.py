import socket
import re
from ExternalProxyHandler import ExternalProxyHandler
import os
import pickle
import numpy as np
import sklearn

FAKE_PORT = 800
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world

class ExternalHTTPProxyHandler(ExternalProxyHandler):
    
    def extract_statistics_from_code(self, code):
        statistic = []
        for block in code:
            if block == '':
                continue
            lines = block.split("\n")
            lines = [line for line in lines if line.strip() and not line.strip().startswith("//")]
            average_line_lenght = sum([len(line) for line in lines]) / len(lines)
            keywords = ['if', 'else', 'for', 'while', 'int', 'float', 'double', 'void', 'long', 'short', 'signed', 'unsigned', 'const', 'static', 'extern', 'auto', 'register', 'volatile', 'typedef', 'struct', 'union', 'enum', 'return', 'break', 'continue', 'switch', 'case', 'goto', '#include', '#define', '#undef', '#ifdef', '#ifndef', '#if', '#elif', '#else', '#endif']
            special_chars = ['{', '}', '(', ')', '[', ']', '*', '&', '==', '!=', '>', '<', '>=', '<=', '++', '--', '+', '-', '*', '/', '%', '&&', '||', '!', '~', '^', '|', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>', '<<=', '>>=', ',', '->', '.', '?', ':']
            keywords_count = sum([sum([line.count(keyword) for keyword in keywords]) for line in lines])
            special_chars_count = sum([sum([line.count(char) for char in special_chars]) for line in lines])
            fraction_keywords = keywords_count / sum([len(line) for line in lines])
            fraction_special_chars = special_chars_count / sum([len(line) for line in lines])
            amount_of_lines_with_semicolon = sum([1 for line in lines if line.endswith(";")]) / len(lines)
            statistic.append((average_line_lenght, fraction_keywords, fraction_special_chars, amount_of_lines_with_semicolon))
        return statistic


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
        

    
    """ Represents HTTP proxy connection """

    def c_detect(self, message):
        """ Enforces the content type """
        splited_msg = message.split('\r\n')
        body = "".join(splited_msg[splited_msg.index(""):])
        print(body)
        
        current_directory = os.getcwd()
        model_name = 'finalized_model_ver2.sav'
        path = current_directory + "/" + model_name
        print(path)

        loaded_model = pickle.load(open(path, 'rb')) # we load the model
        print("Model loaded")
        body_statistics = self.extract_statistics_from_code([body])
        print("Statistics extracted")
        prediction = loaded_model.predict(body_statistics)
        print("Prediction made")
        print(prediction)
        


    def perform_client_connection(self):
        print("Performing client connection")
        while self.is_alive() and not self.done:
            request = self.recv_info(self.csocket)
            if request:
                self.c_detect(request)
                self.ssocket.sendall(request.encode())
            else:
                self.done = True


    def perform_server_connection(self):
        print("Performing server connection")
        while not self.done:
            response = self.recv_info(self.ssocket)
            if response:
                if True:
                    self.csocket.sendall(response.encode())
                else:
                    print("HTTP packet dropped")
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
        proxy = ExternalHTTPProxyHandler(connection, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


    