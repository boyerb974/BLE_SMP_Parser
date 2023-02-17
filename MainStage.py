import pyshark
import Authentication as Aut
import Child12
import Child15
import sys
import getopt
from colorama import Fore

class MainStage():

    def __init__(self,path) -> None:
        self.path = path
        self.smp_pkt = pyshark.FileCapture(path, display_filter = 'btsmp')          #Filter to have only btsmp packets

        self.number_of_pkt = 0

        self.Central_name = ""
        self.Peripheral_name = ""
        self.smp_pkt_name_list = []

        self.smp_pkt_list = []
        self.fill_smp_pkt_list()
        
        self.list_connections_number = self.connections_number()

        self.smp_pkt_list_obj = []
        self.fill_smp_pkt_list_obj()


    def connections_number(self):
        Empty = False
        pck_number = []
        cnt = 0
        while(not Empty):
            try :
                smp_pkt0 = self.smp_pkt_list[cnt]
                smp_pkt1 = self.smp_pkt_list[cnt+1]
                key = smp_pkt0.io_capability + "," + smp_pkt1.io_capability
                if Aut.Mapping_IO_Capabilities[key] == 0 : 
                    pck_number.append(12)
                    cnt += 12
                else :
                    pck_number.append(15)
                    cnt += 15
            except:
                #print("Out of range")
                Empty = True
        return pck_number

    def fill_smp_pkt_list_obj(self):
        cnt = 0
        for pkt in self.list_connections_number:
            if pkt == 12 :
                self.smp_pkt_list_obj.append(Child12.Child12(self.smp_pkt_list[cnt:cnt+pkt]))
                self.smp_pkt_name_list.append(self.smp_pkt[cnt]["BTHCI_ACL"].src_name) 
                self.smp_pkt_name_list.append(self.smp_pkt[cnt]["BTHCI_ACL"].dst_name)
                cnt +=pkt
            else:
                self.smp_pkt_list_obj.append(Child15.Child15(self.smp_pkt_list[cnt:cnt+pkt]))
                self.smp_pkt_name_list.append(self.smp_pkt[cnt]["BTHCI_ACL"].src_name) 
                self.smp_pkt_name_list.append(self.smp_pkt[cnt]["BTHCI_ACL"].dst_name)
                cnt +=pkt

    def fill_smp_pkt_list(self):
        for pkt in self.smp_pkt:
            self.smp_pkt_list.append(pkt["btsmp"])
            self.number_of_pkt +=1

    def print_number_of_smp_pkt(self):
        print(Fore.RED + "This capture has : ",Fore.GREEN + str(self.number_of_pkt), Fore.RED +" SMP packets")
        print(Fore.RESET)
    
    def print_connections_number(self):
        print(Fore.RED + "There are :",Fore.GREEN + str(len(self.list_connections_number)), Fore.RED +"connections\n")
        print(Fore.RESET)

    def print_number_of_pkt_and_connections(self):
        print(Fore.RED + "This capture has : ",Fore.GREEN + str(self.number_of_pkt), Fore.RED +" SMP packets and there are",Fore.GREEN + str(len(self.list_connections_number)), Fore.RED +"connections detected\n")

    def print_connections(self):
        cnt = 0
        cnt1 = 1
        for i in self.smp_pkt_list_obj:
            print(Fore.RED + "This is the report of the connection ",Fore.GREEN + str(cnt1) ,Fore.RED +" between",Fore.YELLOW+ self.smp_pkt_name_list[2*cnt] ,Fore.RED+"and" ,Fore.YELLOW+ self.smp_pkt_name_list[2*cnt+1],"\n")
            i.SMP_script()
            cnt += 1
            cnt1 += 1

def main(argv):
    print(argv)
    arg_input = ""
    arg_output = ""
    arg_help = "{0} -i <input> -o <output>".format(argv[0])
    
    try:
        opts, args = getopt.getopt(argv[1:], "hi:o:", ["help", "input=", 
         "output="])
    except:
        print(arg_help)
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(arg_help)  # print the help message
            sys.exit(2)
        elif opt in ("-i", "--input"):
            arg_input = arg
        elif opt in ("-o", "--output"):
            arg_output = arg

    print('input:', arg_input)
    print('output:', arg_output)
   
    smp_pkt = MainStage(arg_input)
    if arg_output != "":
        with open(arg_output,'w') as sys.stdout:
          print("\n")
          smp_pkt.print_number_of_pkt_and_connections()
          smp_pkt.print_connections()
    else : 
        print("\n")
        smp_pkt.print_number_of_pkt_and_connections()
        smp_pkt.print_connections()
        
if __name__ == "__main__":
    main(sys.argv)





