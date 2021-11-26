#DoIPScan is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
    
#DoIPScan is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
    
#You should have received a copy of the GNU General Public License
#along with DoIPScan.  If not, see <https://www.gnu.org/licenses/>.

import socket
from time import sleep
from scapy.contrib.automotive import doip
from scapy.contrib.automotive import uds

#Possible response in Hex from ECU
response = {
        0x11 : "Service is not supported by the ECU",
        0x12 : "SubFunction not supported by the ECU",
        0x13 : "Service is available",
        0x31 : "Request out of range",
        0x33 : "Security access denied",
        0x70 : "Upload/Download denied",
        0x7E : "Access denied to service",
        0x7F : "Access denied to service"
        }

#Documented services
service_generic = {
        0x10: "Diagnostic Session Control",
        0x11: "ECU Reset",
        0x14: "Clear Diagnostic Information",
        0x19: "Read DTC Information",
        0x22: "Read Data By Identifier",
        0x23: "Read Memory By Address",
        0x24: "Read Scaling Data By Identifier",
        0x27: "Security Access",
        0x28: "Communication Control",
        0x2A: "Read Data By Periodic Identifier",
        0x2C: "Dynamically Define Data Identifier",
        0x2E: "Write Data By Identifier",
        0x2F: "Input Output Control By Identifier",
        0x31: "Routine Controle",
        0x34: "Request Donwload",
        0x35: "Request Upload",
        0x36: "Transfer Data",
        0x37: "Request Transfer Exit",
        0x38: "Request File Transfer",
        0x3D: "Write Memory By Address",
        0x3E: "Tester Present",
        0x83: "Access Timing Parameters",
        0x84: "Secured Data Transmission",
        0x85: "Control DTC Settings",
        0x86: "Response On Event",
        0x87: "Link Control"
        }

class Scan:
    

    def __init__(
            self,
            ecu_ip_adress,
            ecu_logical_adress,
            client_logical_adress=0xe80
            ):

        self.ecu_ip_adress         = ecu_ip_adress
        self.ecu_logical_adress    = ecu_logical_adress
        self.client_logical_adress = client_logical_adress


    def connect(self):

        self.sock                  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        try:
            self.sock.connect((self.ecu_ip_adress,13400))
        except:
            pass

    def process_reply(self,packet,i,session):

        #Converts raw packet to protocol layers recieved using Scapy
        doip_layer = doip.DoIP(packet)
        uds_layer = uds.UDS(doip_layer.payload.original)

        try:
            service = service_generic[i]
        except:
            service = "{} (Undocumented)".format(hex(i))
    
        if uds_layer.service == 0x0:
            return

        if uds_layer.service == 0x7f:

            if uds_layer.negativeResponseCode == 0x11 or uds_layer.negativeResponseCode == 0x12:
                self.not_implemented.append(i)
    
            elif uds_layer.negativeResponseCode == 0x13:
                self.available.append(i)
                print("{} is available".format(service))
        
            elif uds_layer.negativeResponseCode == 0x7E or uds_layer.negativeResponseCode == 0x7F:
                self.access_denied.append(i)
                print("{}: Access Denied in session \"{}\"".format(service,session))

            elif uds_layer.negativeResponseCode == 0x33: 
                self.security_access.append(i)
                print("{}: Security Access Denied".format(service))
            
        else:
            self.undocumented.append((service,uds_layer))

    def session_control(self,session):

        self.not_implemented       = list()
        self.available             = list()
        self.access_denied         = list()
        self.security_access       = list()
        self.undocumented          = list()


        self.connect()

        doip_layer = doip.DoIP(payload_type=0x0005,source_address=self.client_logical_adress)    
        pack = doip_layer    
        self.sock.send(bytes(pack))

        if session != '':

            if session == '\x01':
                print('\033[92m'+"Scanning with Programming Session (1001)" + '\033[0m')
                sess = "Programming Session"
            elif session == '\x02':
                print('\033[92m'+"Scanning with Extended Diagnostic Session (1002)" + '\033[0m')
                sess = "Extended Diagnostic Session"
            elif session == '\x03':
                print('\033[92m'+"Scanning with Safety system diagnostic session (1003)" + '\033[0m')
                sess = "Safety system diagnostic session"

            try:        
                doip_layer = doip.DoIP(payload_type=0x8001,
                        source_address=self.client_logical_adress,
                        target_address=self.ecu_logical_adress)    

                uds_layer = uds.UDS(service=0x10)
                uds_layer.add_payload(session)
                pack = doip_layer/uds_layer    
                self.sock.send(bytes(pack))    
    
                reply_2 = self.sock.recv(4096)
                reply = self.sock.recv(4096)

            except:
                self.sock.close()  
                return

        else:
            sess = "No Session"

            
        try:
            i=0    
    
            #During testing phase I found that Scapy sends 0x00 when I was trying to send 0x40    
            while i < 0x40:    
                
                #Investigate why 0x3b service blacklists host    
                if i==0x3b or i == 0x10:    
                    i+=1    
                    continue    
       
                doip_layer = doip.DoIP(payload_type=0x8001,
                        source_address=self.client_logical_adress,
                        target_address=self.ecu_logical_adress)    

                uds_layer = uds.UDS(service=i)    
                pack = doip_layer/uds_layer    
    
                self.sock.send(bytes(pack))    
    
                #Wait for ecu reply: ECU replies with 2 packets (Response and DoIP message ACK)    
                #The order of reception is not guarenteed and therefore we need to process both packets                        
                reply_2 = self.sock.recv(4096)
                reply = self.sock.recv(4096)    
                self.process_reply(reply,i,sess)    
                self.process_reply(reply_2,i,sess)    
                i+=1
    
        finally:    
            self.sock.close()  

