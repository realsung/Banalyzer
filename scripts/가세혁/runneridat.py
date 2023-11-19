import os
import paramiko
from scp import SCPClient, SCPException

class SSHManager:
    def __init__(self,HOSTNAME,USERNAME,PASSWORD):
        self.ssh_client = None
        self.HOSTNAME = HOSTNAME
        self.USERNAME = USERNAME
        self.PASSWORD = PASSWORD
        self.CWE = None
        self.idaPythonScript = None
        self.create_ssh_client()


    def create_ssh_client(self):
        if self.ssh_client is None:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.HOSTNAME, username=self.USERNAME, password=self.PASSWORD)
        else:
            print("SSH client session exist.")

    def close_ssh_client(self):
        self.ssh_client.close()

    def send_file(self):
        try:
            with SCPClient(self.ssh_client.get_transport()) as scp:
                self.send_command("mkdir C:\\Windows\\Temp\\" + self.USERNAME + "\\script\\")
                scp.put(self.idaPythonScript, "/Windows/Temp/" + self.USERNAME + "/script/" , preserve_times=True)
        except SCPException:
            raise SCPException.message

    def get_file(self, remote_path, local_path):
        try:
            with SCPClient(self.ssh_client.get_transport()) as scp:
                scp.get(remote_path, local_path)
        except SCPException:
            raise SCPException.message

    def send_command(self, command):
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        return stdout.readlines()
    
    def run_idat(self):
        self.send_command("C:\\Users\\Public\\idatclient.py " + self.CWE + " C:\\Windows\\Temp\\" + self.USERNAME + "\\script\\" + self.idaPythonScript + " C:\\Windows\\Temp\\" + self.USERNAME + "\\result.txt")
        print("C:\\Users\\Public\\idatclient.py " + self.CWE + " C:\\Windows\\Temp\\" + self.USERNAME + "\\script\\" + self.idaPythonScript + " C:\\Windows\\Temp\\" + self.USERNAME + "\\result.txt")
        ret = self.get_file("C:\\Windows\\Temp\\" + self.USERNAME + "\\result.txt", "./result.txt")
        self.close_ssh_client()
        return ret
    
scppass = open("scppass", "r").read()
host = open("host", "r").read()
user = open("user", "r").read()

server = SSHManager(host, user, scppass)
server.idaPythonScript = "fsb.py"
server.CWE = "134"
server.send_file()
print(server.run_idat())
