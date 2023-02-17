from colorama import Fore
import ParentClass
from Crypto.Cipher import AES 
import binascii

class Child12(ParentClass.ParentClass):
    
    def __init__(self,smp_pkt) -> None:

        super().__init__(smp_pkt)

        """ pkti SMP Layer"""
        self.smp_pkt0 = self.smp_pkt_list[0]
        self.smp_pkt1 = self.smp_pkt_list[1]
        self.smp_pkt2 = self.smp_pkt_list[2]
        self.smp_pkt3 = self.smp_pkt_list[3]
        self.smp_pkt4 = self.smp_pkt_list[4]
        self.smp_pkt5 = self.smp_pkt_list[5]
        self.smp_pkt6 = self.smp_pkt_list[6]
        self.smp_pkt7 = self.smp_pkt_list[7]
        self.smp_pkt8 = self.smp_pkt_list[8]
        self.smp_pkt9 = self.smp_pkt_list[9]
        self.smp_pkt10 = self.smp_pkt_list[10]
        self.smp_pkt11 = self.smp_pkt_list[11]

    
        """Phase 2 Attributes"""

        self.MConfirm_Value = None
        self.SConfirm_Value = None
        self.MRand_Value = None
        self.SRandValue = None

        """Phase 3 Attributes"""
        self.LTK = None
        self.EDIV = None 
        self.Rand_Value_phase3 = None
        self.Signature_Key = None

        """Fill the attributes"""
        self.fill_attributes_phase1()
        self.fill_attributes_phase2()
        self.fill_attributes_phase3()
        self.mapping_Mio_capability()           
        self.mapping_Sio_capability()           
        self.mapping_Moob_data_flags()          
        self.mapping_Soob_data_flags()          
        self.mapping_Mbonding_flags()           
        self.mapping_Sbonding_flags()           

    def fill_attributes_phase2(self):
        self.MConfirm_Value = self.smp_pkt2.cfm_value.raw_value
        self.SConfirm_Value = self.smp_pkt3.cfm_value.raw_value
        self.MRand_Value = self.smp_pkt4.random_value.raw_value
        self.SRand_Value = self.smp_pkt5.random_value.raw_value

    def fill_attributes_phase3(self):
        self.LTK = self.smp_pkt6.long_term_key.raw_value
        self.EDIV = self.smp_pkt7.ediv
        self.Rand_Value_phase3 = self.smp_pkt7.random_value.raw_value
        self.Signature_Key = self.smp_pkt8.signature_key.raw_value
        self.IRK = self.smp_pkt9.id_resolving_key.raw_value
        self.BD_ADDR = self.smp_pkt10.bd_addr
        self.CSRK = self.smp_pkt11.signature_key.raw_value

    def phase2(self):
        print(Fore.CYAN +"\t\t\t\t\t\t\t Phase 2 : Key establishment and optional authentication\n")
        print(Fore.YELLOW +"(Central -> Peripheral) ",Fore.GREEN + "MConfirm Value : ",Fore.RED + str(self.MConfirm_Value))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "SConfirm Value : ",Fore.RED + str(self.SConfirm_Value))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "MRand Value : ",Fore.RED + str(self.MRand_Value))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "SRand Value : ",Fore.RED + str(self.SRand_Value)+"\n")
        print(Fore.GREEN+"The STK is :", Fore.RED+ "0x"+self.computeSTK().hex())
        print(Fore.RESET)
    
    def phase3(self):
        print(Fore.CYAN +"\t\t\t\t\t\t\t\t\t Phase 3 : Key Distribution\n")
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Long Term Key : ",Fore.RED + str(self.LTK))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Encrypted Diversifier (EDIV) : ",Fore.RED + str(self.EDIV), Fore.GREEN +"\t Random Value : ",Fore.RED +str(self.Rand_Value_phase3))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Signature Key : ",Fore.RED + str(self.Signature_Key))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Identity Resolving Key (IRK): ",Fore.RED + str(self.IRK))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "BD_ADDR : ",Fore.RED + str(self.BD_ADDR))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Connection Signature Resolving Key (CSRK) : ",Fore.RED + str(self.CSRK),"\n")
        print(Fore.RESET)

    def computeSTK(self):
        key = 0x0
        TK = bytes.fromhex("{0:0{1}x}".format(key,32))
        r1,r2 = self.SRand_Value,self.MRand_Value
        r1,r2 = r1[16::],r2[16::]
        r = r1+r2
        return self.e(TK,bytes.fromhex(r))
    
    def e(self,key,plaintextData):
        cipher = AES.new(key, AES.MODE_CCM)
        ciphertext = cipher.encrypt(plaintextData)
        return ciphertext

