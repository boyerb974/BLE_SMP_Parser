import pyshark
from colorama import Fore
from abc import ABC, abstractmethod
import Authentication as Aut

class ParentClass(ABC):

    def __init__(self,smp_pkt) -> None:   
        self.smp_pkt_list = smp_pkt 
        self.number_of_pkt = len(smp_pkt)
        self.key = None

        """Phase 1 Attributes"""

        self.Mio_capability = None
        self.str_Mio_capability = None
        self.Sio_capability = None
        self.str_Sio_capability = None
        self.Moob_data_flags = None  
        self.str_Moob_data_flags = None 
        self.Soob_data_flags = None
        self.str_Soob_data_flags = None 
        self.Mauthreq = None
        self.Sauthreq = None
        self.Mreserved_flags = None
        self.Sreserved_flags = None
        self.Mkeypress_flag = None
        self.Skeypress_flag = None
        self.Msc_flag = None
        self.Ssc_flag = None
        self.Mmitm_flag = None
        self.Smitm_flag = None
        self.Mbonding_flags = None
        self.str_Mbonding_flags = None
        self.Sbonding_flags = None
        self.str_Sbonding_flags = None
        self.Mmax_enc_key_size = None
        self.Smax_enc_key_size = None
        self.entropy = None
        self.Minitiator_key_distribution = None
        self.Sinitiator_key_distribution = None
        self.Mkey_dist_reserved = None
        self.Skey_dist_reserved = None
        self.Mkey_dist_linkkey = None
        self.Skey_dist_linkkey = None
        self.Mkey_dist_sign = None
        self.Skey_dist_sign = None
        self.Mkey_dist_id = None
        self.Skey_dist_id = None
        self.Mkey_dist_enc = None
        self.Skey_dist_enc = None
        self.Mresponder_key_distribution = None
        self.Sresponder_key_distribution = None
        
        self.str_pairing_method = None

        """Phase 3 Attributes"""
        
        self.IRK = None 
        self.BD_ADDR = None 
        self.CSRK = None 


    def fill_attributes_phase1(self):
        self.Mio_capability = self.smp_pkt0.io_capability
        self.Sio_capability = self.smp_pkt1.io_capability
        self.Moob_data_flags = self.smp_pkt0.oob_data_flags
        self.Soob_data_flags = self.smp_pkt1.oob_data_flags
        self.Mauthreq = self.smp_pkt0.authreq
        self.Sauthreq = self.smp_pkt1.authreq
        self.Mreserved_flags = self.smp_pkt0.reserved_flags
        self.Sreserved_flags = self.smp_pkt1.reserved_flags
        self.Mkeypress_flag = self.smp_pkt0.keypress_flag
        self.Skeypress_flag = self.smp_pkt1.keypress_flag
        self.Msc_flag = self.smp_pkt0.sc_flag
        self.Ssc_flag = self.smp_pkt1.sc_flag
        self.Mmitm_flag = self.smp_pkt0.mitm_flag
        self.Smitm_flag = self.smp_pkt1.mitm_flag
        self.Mbonding_flags = self.smp_pkt0.bonding_flags
        self.Sbonding_flags = self.smp_pkt1.bonding_flags
        self.Mmax_enc_key_size = self.smp_pkt0.max_enc_key_size 
        self.Smax_enc_key_size = self.smp_pkt1.max_enc_key_size 
        self.entropy = min(self.Mmax_enc_key_size,self.Smax_enc_key_size)
        self.Minitiator_key_distribution = self.smp_pkt0.initiator_key_distribution
        self.Sinitiator_key_distribution = self.smp_pkt1.initiator_key_distribution
        self.Mkey_dist_reserved = self.smp_pkt0.key_dist_reserved
        self.Skey_dist_reserved = self.smp_pkt1.key_dist_reserved
        self.Mkey_dist_linkkey = self.smp_pkt0.key_dist_linkkey
        self.Skey_dist_linkkey = self.smp_pkt1.key_dist_linkkey
        self.Mkey_dist_sign = self.smp_pkt0.key_dist_sign
        self.Skey_dist_sign = self.smp_pkt1.key_dist_sign
        self.Mkey_dist_id = self.smp_pkt0.key_dist_id
        self.Skey_dist_id = self.smp_pkt1.key_dist_id
        self.Mkey_dist_enc = self.smp_pkt0.key_dist_enc
        self.Skey_dist_enc = self.smp_pkt1.key_dist_enc
        self.Mresponder_key_distribution = self.smp_pkt0.responder_key_distribution
        self.Sresponder_key_distribution = self.smp_pkt1.responder_key_distribution
        self.key = self.smp_pkt0.io_capability + "," + self.smp_pkt1.io_capability
        self.str_pairing_method = self.pairing_method()

    @abstractmethod
    def fill_attributes_phase2(self):
        pass
    @abstractmethod
    def fill_attributes_phase3(self):
        pass
################################### TO CHANGE ######################################

    def mapping_Mio_capability(self):
        if self.Mio_capability == "0x00":
            self.str_Mio_capability = "DisplayOnly"
        elif self.Mio_capability == "0x01":
            self.str_Mio_capability = "DisplayYesNo"
        elif self.Mio_capability == "0x02":
            self.str_Mio_capability = "KeyboardOnly"
        elif self.Mio_capability == "0x03":
            self.str_Mio_capability = "NoInputNoOutput"    
        elif self.Mio_capability == "0x04":
            self.str_Mio_capability = "KeyboardDisplay"
        else :
            self.str_Mio_capability = "Error in io_capability"
         
    def mapping_Sio_capability(self):
        if self.Sio_capability == '0x00':
            self.str_Sio_capability = "DisplayOnly"
        elif self.Sio_capability == '0x01':
            self.str_Sio_capability = "DisplayYesNo"
        elif self.Sio_capability == '0x02':
            self.str_Sio_capability = "KeyboardOnly"
        elif self.Sio_capability == '0x03':
            self.str_Sio_capability = "NoInputNoOutput"    
        elif self.Sio_capability == '0x04':
            self.str_Sio_capability = "KeyboardDisplay"
        else :
            self.str_Sio_capability = "Error in io_capability"
    
    def mapping_Moob_data_flags(self):
        if self.Moob_data_flags == '0x00' :
            self.str_Moob_data_flags = "OOB Authentication data not present"
        elif self.Moob_data_flags == '0x01' :
            self.str_Moob_data_flags = "OOB Authentication data from remote device present"
        else : 
            self.str_Moob_data_flags = "Error in oob_data_flags"

    def mapping_Soob_data_flags(self):
        if self.Soob_data_flags == '0x00' :
            self.str_Soob_data_flags = "OOB Authentication data not present"
        elif self.Soob_data_flags == '0x01' :
            self.str_Soob_data_flags = "OOB Authentication data from remote device present"
        else : 
            self.str_Soob_data_flags = "Error in oob_data_flags"
        
    def mapping_Mbonding_flags(self):
        if self.Mbonding_flags == '0x00' :
            self.str_Mbonding_flags = "No Bonding"
        elif self.Mbonding_flags == '0x01' :
            self.str_Mbonding_flags = "Bonding"
        else : 
            self.str_Mbonding_flags = "Error in bonding_flags"

    def mapping_Sbonding_flags(self):
        if self.Sbonding_flags == '0x00' :
            self.str_Sbonding_flags = "No Bonding"
        elif self.Sbonding_flags == '0x01' :
            self.str_Sbonding_flags = "Bonding"
        else : 
            self.str_Sbonding_flags = "Error in bonding_flags"

#########################################################################################

    def SMP_script(self):
        self.phase1()
        self.phase2()
        self.phase3()

    def pairing_method(self):
        mapping = Aut.Mapping_IO_Capabilities[self.key]
        if mapping == 0 : 
            pairing_method = "JustWork Unauthenticated" # JustWork Unauthenticated = 0   --> 12 packets
        elif mapping == 1 : 
            pairing_method = "Passkey Entry : responder displays, initiator inputs Auhenticated"  # Passkey Entry : responder displays, initiator inputs Auhenticated = 1 --> Assume 15 packets
        elif mapping == 2 : 
            pairing_method = "Passkey Entry : initiator displays, responder inputs Auhenticated"  # Passkey Entry : initiator displays, responder inputs Auhenticated = 2 --> 15 packets
        elif mapping == 2 : 
            pairing_method = "Passkey Entry : initiator and responder inputs Auhenticated"        # Passkey Entry : initiator and responder inputs       Auhenticated = 3 --> Assume 15 packets
        return pairing_method

    def phase1(self):
        print(Fore.CYAN +"\t\t\t\t\t\t\t Phase 1 : Exchange of pairing information\n")

        print(Fore.YELLOW +"(Central)" ,Fore.GREEN+"   Secure Connections flag is : ",Fore.RED +  self.Msc_flag )
        print(Fore.YELLOW +"(Peripheral)" ,Fore.GREEN+"Secure Connections flag is : ",Fore.RED +  self.Ssc_flag )
        if ((self.Msc_flag == "1") & (self.Ssc_flag == "1")): print(Fore.MAGENTA+"LE Secure Connections\n")
        else : print(Fore.MAGENTA+"LE Legacy (=Secure Simple Pairing)\n")


        print(Fore.YELLOW +"(Central)" ,Fore.GREEN+"   OOB Data Flag is : ",Fore.RED +  self.Moob_data_flags ,"->",self.str_Moob_data_flags)
        print(Fore.YELLOW +"(Peripheral)" ,Fore.GREEN+"OOB Data Flag is : ",Fore.RED +  self.Soob_data_flags ,"->",self.str_Soob_data_flags)

        if ((self.Moob_data_flags == "0x01") & (self.Soob_data_flags == "0x01")): print(Fore.MAGENTA+"Use of the pairing method : Out Of Band\n")
        else : print(Fore.MAGENTA+"Unable to use the pairing method : Out Of Band"); print(Fore.MAGENTA+"Just Works or Passkey Entry?\n")

        print(Fore.YELLOW +"(Central)" ,Fore.GREEN+"   MITM flag is : ",Fore.RED +  self.Mmitm_flag )
        print(Fore.YELLOW +"(Peripheral)" ,Fore.GREEN+"MITM flag is : ",Fore.RED +  self.Smitm_flag )
        if ((self.Smitm_flag == "1") & (self.Smitm_flag == "1")): print(Fore.MAGENTA+"Use of the pairing method : Just Work at least\n")
        else : print(Fore.MAGENTA+"We should check at the IO Capability now \n")

        print(Fore.YELLOW +"(Central)" ,Fore.GREEN+"   IO Capability is : ",Fore.RED +  self.Mio_capability ,"->",self.str_Mio_capability)
        print(Fore.YELLOW +"(Peripheral)" ,Fore.GREEN+"IO Capability is : ",Fore.RED +  self.Sio_capability ,"->",self.str_Sio_capability)
        print(Fore.MAGENTA+"Use of the pairing method : "+ self.str_pairing_method +"\n")#self.pairing_method)
        
        print(Fore.GREEN+"The Entropy of the encryption key is :", Fore.RED+ self.entropy)
        print(Fore.RESET)

        
        print(Fore.YELLOW +"(Central)" ,Fore.GREEN+"   Link Key Flag of Init is: ",Fore.RED +  self.hex2bit(self.Minitiator_key_distribution)[0],Fore.GREEN+"   Link Key Flag of Resp is: ",Fore.RED +  self.hex2bit(self.Mresponder_key_distribution)[0] )
        print(Fore.YELLOW +"(Peripheral)" ,Fore.GREEN+"Link Key Flag of Init is : ",Fore.RED +  self.hex2bit(self.Sinitiator_key_distribution)[0],Fore.GREEN+"   Link Key Flag of Resp is: ",Fore.RED +  self.hex2bit(self.Mresponder_key_distribution)[0] )
        if ((self.hex2bit(self.Minitiator_key_distribution)[0] == "1") & (self.hex2bit(self.Sinitiator_key_distribution)[0] == "1") & (self.hex2bit(self.Mresponder_key_distribution)[0] == "1") & (self.hex2bit(self.Sresponder_key_distribution)[0] == "1")): 
            print(Fore.MAGENTA+"Cross-Transport Key Derivation (CTKD) negotiated\n")
        else : 
            print(Fore.MAGENTA+"Cross-Transport Key Derivation (CTKD) not negotiated\n")
       

    @abstractmethod
    def phase2():
        pass
    @abstractmethod
    def phase3():
        pass

    def hex2bit(self,my_hexdata):
        scale = 16 ## equals to hexadecimal
        num_of_bits = 4
        return bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
    
    