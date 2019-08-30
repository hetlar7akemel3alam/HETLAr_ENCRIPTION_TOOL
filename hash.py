import os,sys,hashlib
print ("welcome to HETLAR 7AKEM EL3ALAM Encrypt tool")
print ("phone:201148422820")
print ("+---------------------------------+")
print ("| [+] HETLAR 7AKEM EL3ALAM   [+]  |")
print ("| [+]      Ma7moud med7at    [+]  |")
print ("| [+]        Database_HK     [+]  |")
print ("+---------------------------------+")
print ("1-base16")
print ("2-base32")
print ("3-base64")
print ("4-SHA-1")
print ("5-SHA-224")
print ("6-SHA-256")
print ("7-SHA-384")
print ("8-SHA-512")
print ("9-md5")
print ("100-exit")
print ("            " + "                " + "                ")
print ("|Dont forget to put quotation marks when you enter the text to be encrypted or decrypted with regards (HETLAR)|")
print ("            " + "                " + "                ")
HETLAR = input("HETLAR>>>")
if HETLAR ==  1  :
        import base64
        print ("1-encrypt")
        print ("2-decrypt")
        HETLAR = input ("HETLAR>>>")
        if HETLAR ==  1  :
                encrypt = input ("enter anything for encryption :")
                tr = base64.b16encode(encrypt)
                print ("your decryption" + tr)
        elif HETLAR ==  2  :
                decrypt = input ("enter anything for decryption :")
                rt = base64.b16decode(decrypt)
                print ("your decryption" + rt)
elif HETLAR ==  2  :
        import base64
        print ("1-encrypt")
        print ("2-decrypt")

        HETLAR = input ("HETLAR>>>")
        if HETLAR ==  1  :
                encrypt = input ("enter anything for encryption :")
                re = base64.b32encode(encrypt)
                print ("your encrytion" + re)
        elif HETLAR ==  2  :
                decrypt = input ("enter anything decryption :")
                er = base64.b32decode(decrypt)
                print ("your decryption" + er)
if HETLAR ==3:
        import base64
        print ("1-Encrypt")
        print ("2-Decrypt")

        HETLAR = input("HETLAR>>>")
        if HETLAR ==  1  :
            encrypt = input("Enter anything for Encryption : ")
            en = base64.b64encode(encrypt)
            print ("Your Decryption :" +en)
        elif HETLAR  ==  2  :
            decrypt = input("Enter anything for Decryption: ")
            de = base64.b64decode(decrypt)
            print ("Your Decryption :" + de)
        elif HETLAR ==  4  :
                in_user = input("Enter anything for Encryption : ")
                sha1 = hashlib.sha1(in_user).hexdigest()
                print ("Your Decryption :" + sha1)
elif HETLAR ==  5  :
    in_user = input("Enter anything for Encryption : ")
    sha224 = hashlib.sha224(in_user).hexdigest()
    print ("Your Decryption :" + sha224)

elif HETLAR  ==  6  :
    in_user = input("Enter anything for Encryption : ")
    sha256 = hashlib.sha256(in_user).hexdigest()
    print ("Your Decryption :" + sha256)
elif HETLAR  ==  7  :
    in_user = input("Enter anything for Encryption : ")
    sha384 = hashlib.sha384(in_user).hexdigest()
    print ("Your Decryption :" + sha384)
elif HETLAR ==  8  :
    in_user = input("Enter anything for Encryption : ")
    sha512 = hashlib.sha512(in_user).hexdigest()
    print ("Your Decryption :" + sha512)
elif HETLAR  ==  9  :
    in_user = input("Enter anything for Encryption : ")
    md5 = hashlib.md5(in_user).hexdigest()
    print ("Your Decryption :" + md5)

elif HETLAR ==  100  :
    print ("close encrypt and decrypt")
    sys.exit()
else:
    print ("thanks for using HETLAR 7AKEM EL3ALAM encryption tool")
