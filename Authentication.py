
"""Dictionnary Key Format : {"IO_Capapility_Responder,IO_Capabality_Initiator":Value} """
# JustWork Unauthenticated = 0   --> 12 packets
# Passkey Entry : responder displays, initiator inputs Auhenticated = 1 --> Assume 15 packets
# Passkey Entry : initiator displays, responder inputs Auhenticated = 2 --> 15 packets
# Passkey Entry : initiator and responder inputs       Auhenticated = 3 --> Assume 15 packets
Mapping_IO_Capabilities = {"0x00,0x00":0,"0x00,0x01":0,"0x00,0x02":1,"0x00,0x03":0,"0x00,0x04":1,
                           "0x01,0x00":0,"0x01,0x01":0,"0x01,0x02":1,"0x01,0x03":0,"0x01,0x04":1,
                           "0x02,0x00":2,"0x02,0x01":2,"0x02,0x02":3,"0x02,0x03":0,"0x02,0x04":2,
                           "0x03,0x00":0,"0x03,0x01":0,"0x03,0x02":0,"0x03,0x03":0,"0x03,0x04":0,
                           "0x04,0x00":2,"0x04,0x01":2,"0x04,0x02":1,"0x04,0x03":0,"0x04,0x04":2,
                            }
#print(Mapping_IO_Capabilities["0x00,0x00"])
#print(Mapping_IO_Capabilities["0x01,0x02"])
#print(Mapping_IO_Capabilities["0x02,0x00"])
#print(Mapping_IO_Capabilities["0x02,0x02"])
















