import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Cryptodome.Hash import SHA3_256, HMAC, SHA256
import requests
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad
import random
import re
import json
import os

API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

stuID = None
IKey_Pr = None
IKey_Pub = None
SPKey_Pr = None
SPKey_Pub = None
OTKs = []


def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (k - sA*h) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False


#server's Identitiy public key
E = Setup()
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441, 93192522080143207888898588123297137412359674872998361245305696362578896786687, E)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    print(response.json())

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

############## The new functions of phase 2 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

############## The new functions of phase 3 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Sending message is: ", key_bundle_msg)
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    #print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        print(response.json()) 
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

################## Phase 1 Implementation ##################
    
def identityKeyGeneration():
    global IKey_Pr, IKey_Pub

    if os.path.exists('Identity_Key.txt'):
        print('You have already registered a pair of keys! Previous keys will be used.')
        keyFile = open('Identity_Key.txt', 'r')

        line = keyFile.readline()
        line = line.split(': ')
        IKey_Pr = int(line[1])

        IKey_Pub = IKey_Pr * E.generator
        assert E.is_on_curve(IKey_Pub)


    else:
        IKey_Pr = Random.new().read(int(math.log(E.order, 2)))
        IKey_Pr = int.from_bytes(IKey_Pr, byteorder='big') % (E.order - 1)

        IKey_Pub = IKey_Pr * E.generator
        assert E.is_on_curve(IKey_Pub)
        print('Public and private keys are generated!')

def signitureGeneration(message):
    k = Random.new().read(int(math.log(E.order - 2, 2)))
    k = int.from_bytes(k, byteorder='big') % E.order

    R = k * E.generator
    r = R.x % E.order

    hashed_message = SHA3_256.new(r.to_bytes((r.bit_length() + 7) // 8, byteorder='big') + message)

    h = int.from_bytes(hashed_message.digest(), byteorder='big') % E.order
    s = (k - IKey_Pr * h) % E.order

    return h, s


def signedPreKeyGeneration():
    global SPKey_Pr, SPKey_Pub

    if os.path.exists('Signed_Pre_Key.txt'):
        print('You have already registered a pair of signed pre-keys! Previous keys will be used.')
        keyFile = open('Signed_Pre_Key.txt', 'r')

        line = keyFile.readline()
        line = line.split(' ')
        SPKey_Pr = int(line[1])

        SPKey_Pub = SPKey_Pr * E.generator
        assert E.is_on_curve(SPKey_Pub) 


    else:
        SPKey_Pr = Random.new().read(int(math.log(E.order, 2)))
        SPKey_Pr = int.from_bytes(SPKey_Pr, byteorder='big') % (E.order - 1)

        SPKey_Pub = SPKey_Pr * E.generator
        assert E.is_on_curve(SPKey_Pub)
        print('Public and private signed pre-keys are generated!')

def generateHMACKey():
    T = SPKey_Pr * IKey_Ser
    t_y = int.to_bytes(T.y, (T.y.bit_length()+7)//8, 'big')
    t_x = int.to_bytes(T.x, (T.x.bit_length()+7)//8, 'big')
    U = b'TheHMACKeyToSuccess' + t_y + t_x
    return SHA3_256.new(U).digest()

def generateKey():
    private_key = Random.new().read(int(math.log(E.order, 2)))
    private_key = int.from_bytes(private_key, byteorder='big') % (E.order - 1)

    public_key = private_key * E.generator
    assert E.is_on_curve(public_key)

    return private_key, public_key

def generateOTKs(HMACKey):
    if os.path.exists("One_Time_Keys.txt"):
        print("Existing OTKs are being used.")
        file = open("One_Time_Keys.txt", "r")
        
        for line in file.readlines():
            OTKs.append(int(line.split(" ")[5]))

    else:
        print(f"Generating OTKs from 0 to 9")
        otk_file = open("One_Time_Keys.txt", 'w')
        for i in range(10):
            privateOTK, publicOTK = generateKey()
            OTKs.append(privateOTK)

            byte_x = int.to_bytes(publicOTK.x, (publicOTK.x.bit_length()+7)//8, 'big')
            byte_y = int.to_bytes(publicOTK.y, (publicOTK.y.bit_length()+7)//8, 'big')
            concatanated = byte_x + byte_y
            hmacValue = HMAC.new(HMACKey, digestmod=SHA256)
            hmacValue.update(concatanated)

            if OTKReg(i, publicOTK.x, publicOTK.y, hmacValue.hexdigest()):
                print(f"Successfully registered OTK #{i}")
                otk_file.write(f"One Time Key #{i} ")
                otk_file.write(f"Private: {privateOTK} ")
                otk_file.write(f"Public.x: {publicOTK.x} ")
                otk_file.write(f"Public.y: {publicOTK.y}")
                otk_file.write(f"\n")
            print()
        otk_file.close()

################## Phase 2 Implementation ##################   
def sessionKeyGeneration(IKPoint, EKPoint, otkID):
    T1 = IKPoint * SPKey_Pr
    T2 = EKPoint * IKey_Pr
    T3 = EKPoint * SPKey_Pr
    T4 = EKPoint * OTKs[otkID]
    U = int.to_bytes(T1.x, (T1.x.bit_length()+7)//8, 'big') + int.to_bytes(T1.y, (T1.y.bit_length()+7)//8, 'big') + int.to_bytes(T2.x, (T2.x.bit_length()+7)//8, 'big') + int.to_bytes(T2.y, (T2.y.bit_length()+7)//8, 'big') + int.to_bytes(T3.x, (T3.x.bit_length()+7)//8, 'big') + int.to_bytes(T3.y, (T3.y.bit_length()+7)//8, 'big') + int.to_bytes(T4.x, (T4.x.bit_length()+7)//8, 'big') + int.to_bytes(T4.y, (T4.y.bit_length()+7)//8, 'big') +b"WhatsUpDoc"
    return SHA3_256.new(U).digest()

def keyDerivationFunction(messageID, sessionKey):
    currIndex = 1
    encKey = None
    hmacKey = None

    while currIndex <= messageID:
        encKey = SHA3_256.new(sessionKey + b"JustKeepSwimming").digest()
        hmacKey = SHA3_256.new(sessionKey + encKey + b"HakunaMatata").digest()
        sessionKey = SHA3_256.new(encKey + hmacKey + b"OhanaMeansFamily").digest()
        currIndex += 1
    
    return encKey, hmacKey

messages = []

################## Phase 3 Implementation ##################
def senderSessionKeyGeneration(IKPoint, EKPr, OTKPoint, SPKPoint):
    T1 = IKey_Pr * SPKPoint
    T2 = EKPr * IKPoint
    T3 = EKPr * SPKPoint
    T4 = EKPr * OTKPoint
    U = int.to_bytes(T1.x, (T1.x.bit_length()+7)//8, 'big') + int.to_bytes(T1.y, (T1.y.bit_length()+7)//8, 'big') + int.to_bytes(T2.x, (T2.x.bit_length()+7)//8, 'big') + int.to_bytes(T2.y, (T2.y.bit_length()+7)//8, 'big') + int.to_bytes(T3.x, (T3.x.bit_length()+7)//8, 'big') + int.to_bytes(T3.y, (T3.y.bit_length()+7)//8, 'big') + int.to_bytes(T4.x, (T4.x.bit_length()+7)//8, 'big') + int.to_bytes(T4.y, (T4.y.bit_length()+7)//8, 'big') +b"WhatsUpDoc"
    return SHA3_256.new(U).digest()

if __name__ == '__main__':
    while True:
        if stuID == None:
            stuID = int(input("What is your student ID? "))
        
        print("Please choose an operation:")
        print("1 - Exit")
        print("2 - Generate keys")
        print("3 - Send signiture")
        print("4 - Authentication of IK")
        print("5 - Reset Identity Keys")
        print("6 - Generate SPK")
        print("7 - Authentication of SPK")
        print("8 - Save current SPK")
        print("9 - Reset SPK")
        print("10 - Generate OTK")
        print("11 - Reset OTK")
        print("12 - Download Messages from Inbox and Display")
        print("13 - Send, Receive and Resend Message (Phase3)")
        
        option = int(input("Select the option: "))

        if option == 1:
            break

        if option == 2:
            identityKeyGeneration()

        elif option == 3:
            if IKey_Pr == None or not E.is_on_curve(IKey_Pub):
                print('Please generate keys first')
            else:
                stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
                signitureH, signitureS = signitureGeneration(stuID_message)
                print(f"Signature of my ID number is:\nh:{signitureH}\ns:{signitureS}")
                IKRegReq(signitureH, signitureS, IKey_Pub.x, IKey_Pub.y)

        elif option == 4:
            verification_code = int(input("Please enter verification code: "))
            IKRegVerify(verification_code)

        elif option == 5:
            verification_code = int(input("Please enter verification code: "))
            ResetIK(verification_code)
            if os.path.exists("Identity_Key.txt"):
                os.remove("Identity_Key.txt")

        elif option == 6:
            if IKey_Pr == None or not E.is_on_curve(IKey_Pub):
                if os.path.exists("Identity_Key.txt"):
                    identityKeyGeneration()
                    signedPreKeyGeneration()
                else:
                    print("Please first generate your key and then register it.")
            else:
                signedPreKeyGeneration()

        elif option == 7:
            if SPKey_Pr == None or not E.is_on_curve(SPKey_Pub):
                print("Please first generate your signed pre key and then register it.")
            else:
                SPKPUB_x_bytes = int.to_bytes(SPKey_Pub.x, (SPKey_Pub.x.bit_length()+7)//8, 'big')
                SPKPUB_y_bytes = int.to_bytes(SPKey_Pub.y, (SPKey_Pub.y.bit_length()+7)//8, 'big')
                message = SPKPUB_x_bytes + SPKPUB_y_bytes

                signitureSPKH, signitureSPKS = signitureGeneration(message)
                print(f"Signature of my SPK is:\nh:{signitureSPKH}\ns:{signitureSPKS}")
                SPKReg(signitureSPKH, signitureSPKS, SPKey_Pub.x, SPKey_Pub.y)

        elif option == 8:
            if SPKey_Pr == None or not E.is_on_curve(SPKey_Pub):
                print("Please first generate your signed pre key and then save it.")
            else:
                file = open('Signed_Pre_Key.txt', 'w')
                file.write(f'Private: {SPKey_Pr} ')
                file.write(f"Public.X: {SPKey_Pub.x} ")
                file.write(f"Public.y: {SPKey_Pub.y} ")
                file.close()

        elif option == 9:
            stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
            signitureH, signitureS = signitureGeneration(stuID_message)
            if ResetSPK(signitureH, signitureS):
                os.remove("Signed_Pre_Key.txt")
                os.remove("One_Time_Keys.txt")
                print("Successfully reset SPK")
            else:
                print("Resetting SPK is unsuccessful")
            
        elif option == 10:
            hmacKey = generateHMACKey()
            generateOTKs(hmacKey)

        elif option == 11:
            stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
            signitureH, signitureS = signitureGeneration(stuID_message)
            print("Trying to delete all OTKs")
            if ResetOTK(signitureH, signitureS):
                print("Deleted all OTKs")
                os.remove("One_Time_Keys.txt")

        elif option == 12:
            #asigning values to global variables(not related with phase 2 implementation)
            identityKeyGeneration()
            signedPreKeyGeneration()
            hmacKey = generateHMACKey()
            generateOTKs(hmacKey)

            print("Checking the inbox for incoming messages")
            print("+++++++++++++++++++++++++++++++++++++++++++++")
            print()
            print("Signing my stuID with my private IK")
            print()
            stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
            signitureH, signitureS = signitureGeneration(stuID_message)
            PseudoSendMsg(signitureH, signitureS)
            print()
            print("+++++++++++++++++++++++++++++++++++++++++++++")
            print()
            for i in range(1, 6):
                stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
                signitureH, signitureS = signitureGeneration(stuID_message)

                senderID, otkID, messageID, msg, IKX, IKY, EKX, EKY = ReqMsg(signitureH, signitureS)
                print()
                print("I got this from client 18007: ", msg)
                print()
                messageByte = int.to_bytes(msg, (msg.bit_length() + 7) // 8, 'big')
                print("Converting message to bytes to decrypt it...")
                print()
                print("Converted message is: ", messageByte)

                senderIKPoint = Point(IKX, IKY, E)
                senderEKPoint = Point(EKX, EKY, E)
                print()
                print("Generating the key Ks, Kenc, & Khmac and then the HMAC value ..")
                sessionKey = sessionKeyGeneration(senderIKPoint, senderEKPoint, otkID)
                encKey, hmacKey = keyDerivationFunction(messageID, sessionKey)

                nonce = messageByte[:8]
                ciphertext = messageByte[8:-32]
                hmacFromMessage = messageByte[-32:]

                hmac = HMAC.new(hmacKey, ciphertext, SHA256).digest()
                print() 
                print("hmac is: ",hmac)

                if hmac == hmacFromMessage:
                    print("Hmac value is verified")
                    AEScipher = AES.new(encKey, AES.MODE_CTR, nonce=nonce)
                    decryptedText = AEScipher.decrypt(ciphertext)
                    plaintext = decryptedText.decode('utf-8')
                    print("The collected plaintext: ", plaintext)
                    messages.append((messageID, plaintext))
                    Checker(stuID, senderID, messageID, plaintext)

                else:
                    print("Hmac value couldn't be verified")
                    Checker(stuID, senderID, messageID, 'INVALIDHMAC')
                print()
                print("+++++++++++++++++++++++++++++++++++++++++++++")
                print()
            
            stuID_message = int.to_bytes(stuID, (stuID.bit_length() + 7) // 8, byteorder='big')
            signitureH, signitureS = signitureGeneration(stuID_message)
            deletedMessages = ReqDelMsg(signitureH, signitureS)
            print()
            print("Checking whether there were some deleted messages!!")
            print("==========================================")

            for message in messages:
                if message[0] in deletedMessages:
                    print(f"Message {message[0]} - Was deleted by sender - X")
                else:
                    print(f"Message {message[0]} - {message[1]} - Read")
            messages= []

        elif option == 13:
            #asigning values to global variables(not related with phase 3 implementation)
            identityKeyGeneration()
            signedPreKeyGeneration()
            hmacKey = generateHMACKey()
            generateOTKs(hmacKey)
            stuIDB = int(input("Enter the ID of receiver student: "))

            print("Signing the stuIDB of party B with my private IK")
            stuIDB_message = int.to_bytes(stuIDB, (stuIDB.bit_length() + 7) // 8, byteorder='big')
            signitureH, signitureS = signitureGeneration(stuIDB_message)
            #print("Requesting party B's OTK ...")
            keyID, IKX, IKY, SPKX, SPKY, H, S, OTKX, OTKY = reqKeyBundle(stuID, stuIDB, signitureH, signitureS)
            print("Verifying the server's SPK...")
            SPKX_bytes = int.to_bytes(SPKX, (SPKX.bit_length() + 7) // 8, byteorder='big')
            SPKY_bytes = int.to_bytes(SPKY, (SPKY.bit_length() + 7) // 8, byteorder='big')
            IKPUB = Point(IKX, IKY, E)
            message = SPKX_bytes + SPKY_bytes
            isValidSignature = SignVer(message, H, S, E, IKPUB )
            print("Is SPK verified?")
            if isValidSignature:
                print("True")
                print("The other party's OTK public key is acquired from the server...")
                
                EKPr, EKPubPoint = KeyGen(E)
                OTKPUB = Point(OTKX, OTKY, E)
                SPKPUB = Point(SPKX, SPKY, E)

                sessionKey = senderSessionKeyGeneration(IKPUB, EKPr, OTKPUB, SPKPUB)
                encKey, hmacKey = keyDerivationFunction(1, sessionKey)

                sending_message = input("Please enter the message: ")
                plaintext = bytes(sending_message, 'utf-8')

                cipher = AES.new(encKey, AES.MODE_CTR)
                messageWoNonce = cipher.encrypt(plaintext)
                hmac = HMAC.new(hmacKey, messageWoNonce, SHA256).digest()

                ciphertext = int.from_bytes(cipher.nonce + messageWoNonce + hmac, byteorder= 'big')

                SendMsg(stuID, stuIDB, keyID, 1, ciphertext, IKey_Pub.x, IKey_Pub.y, EKPubPoint.x, EKPubPoint.y)

            else:
                print("False")

           

        print()
