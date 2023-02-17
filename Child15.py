from colorama import Fore
import ParentClass

class Child15(ParentClass.ParentClass):
    
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
        self.smp_pkt12 = self.smp_pkt_list[12]
        self.smp_pkt13 = self.smp_pkt_list[13]
        self.smp_pkt14 = self.smp_pkt_list[14]

        """Phase 2 Attributes"""

        self.MPublic_Key_X = None
        self.MPublic_Key_Y = None
        self.SPublic_Key_X = None
        self.SPublic_Key_Y = None
        self.SConfirm_Value = None
        self.MRand_Value = None
        self.SRandValue = None
        self.MDHkey_Check = None
        self.SDHkey_Check = None

        """Phase 3 Attributes"""

        self.SIRK = None 
        self.SBD_ADDR = None
        self.SSignature_Key = None

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

        self.key = self.smp_pkt0.io_capability + "," + self.smp_pkt1.io_capability

    def fill_attributes_phase2(self):
        self.MPublic_Key_X = self.smp_pkt2.public_key_x.raw_value
        self.MPublic_Key_Y = self.smp_pkt2.public_key_y.raw_value
        self.SPublic_Key_X = self.smp_pkt3.public_key_x.raw_value
        self.SPublic_Key_Y = self.smp_pkt3.public_key_y.raw_value
        self.SConfirm_Value = self.smp_pkt4.cfm_value.raw_value
        self.MRand_Value = self.smp_pkt5.random_value.raw_value
        self.SRand_Value = self.smp_pkt6.random_value.raw_value
        self.MDHkey_Check = self.smp_pkt7.dhkey_check.raw_value
        self.SDHkey_Check = self.smp_pkt8.dhkey_check.raw_value

    def fill_attributes_phase3(self):
        self.SIRK = self.smp_pkt9.id_resolving_key.raw_value
        self.SBD_ADDR = self.smp_pkt10.bd_addr
        self.SSignature_Key = self.smp_pkt11.signature_key.raw_value
        self.IRK = self.smp_pkt12.id_resolving_key.raw_value
        self.BD_ADDR = self.smp_pkt13.bd_addr
        self.CSRK = self.smp_pkt14.signature_key.raw_value
    
    def phase2(self):
        print(Fore.CYAN +"\t\t\t\t\t\t\t Phase 2 : Key establishment and optional authentication\n")
        print(Fore.YELLOW +"(Central -> Peripheral) ",Fore.GREEN + "Public Key X : ",Fore.RED + str(self.MPublic_Key_X))
        print(Fore.YELLOW +"(Central -> Peripheral) ",Fore.GREEN + "Public Key Y : ",Fore.RED + str(self.MPublic_Key_Y))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Public Key X : ",Fore.RED + str(self.SPublic_Key_X))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Public Key Y : ",Fore.RED + str(self.SPublic_Key_Y))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "SConfirm Value : ",Fore.RED + str(self.SConfirm_Value))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Rand Value : ",Fore.RED + str(self.MRand_Value))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Rand Value : ",Fore.RED + str(self.SRand_Value))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Diffie-Hellman Key : ",Fore.RED + str(self.MDHkey_Check))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Diffie-Hellman Key : ",Fore.RED + str(self.SDHkey_Check))
        print(Fore.RESET)

    def phase3(self):
        print(Fore.CYAN +"\t\t\t\t\t\t\t\t\t Phase 3 : Key Distribution\n")
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Identity Resolving Key (IRK): ",Fore.RED + str(self.SIRK))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "BD_ADDR  : ",Fore.RED + str(self.SBD_ADDR))
        print(Fore.YELLOW +"(Peripheral -> Central) " ,Fore.GREEN + "Signature Key : ",Fore.RED + str(self.SSignature_Key))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Identity Resolving Key (IRK): ",Fore.RED + str(self.IRK))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "BD_ADDR : ",Fore.RED + str(self.BD_ADDR))
        print(Fore.YELLOW +"(Central -> Peripheral) " ,Fore.GREEN + "Connection Signature Resolving Key (CSRK) : ",Fore.RED + str(self.CSRK),"\n")
        print(Fore.RESET)