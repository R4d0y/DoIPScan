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

import scan
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = "ECU Service scanner over DoIP")

    parser.add_argument('-i','--ip',dest='ecu_ip',help="ECU IP Address")

    parser.add_argument('-l','--logical-address',dest="ecu_logical_address",help="ECU Logical Address")

    parser.add_argument('-c','--client-logical-address',dest="client_logical_address",
            help="Client Logical Address")

    args                   = parser.parse_args()

    ecu_ip_address         = args.ecu_ip

    ecu_logical_address    = int(args.ecu_logical_address.replace("0x", ""),16)


    if args.client_logical_address == None:
        scan = scan.Scan(ecu_ip_address,ecu_logical_address)
    else:
        client_logical_address = int(args.client_logical_address.replace("0x", ""),16)
        scan = scan.Scan(ecu_ip_address,ecu_logical_address,client_logical_address)

    print('\033[91m'+"==================Starting scanner===================="+'\033[0m')
    scan.session_control('')
    scan.session_control('\x01')
    scan.session_control('\x02')
    scan.session_control('\x03')

