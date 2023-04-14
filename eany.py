#!/bin/python
#pip install cryptography
#pip install PyInquirer
#Python 3.9.11
from __future__ import print_function, unicode_literals

from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from PyInquirer import prompt
from pprint import pprint


def encodingKey(seed = 'secret seed',password=''):
    s = bytes(seed,'utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=s,
        iterations=390000,
    )

    k = base64.urlsafe_b64encode(kdf.derive(bytes(password,'utf-8')))
    f = Fernet(k)
    return f,k
def encodeFile(key):
    with open('content.txt','rb') as de_file:
        txt = de_file.read()
        de_file.close()

    token = key.encrypt(txt)

    with open('content.txt','wb') as en_file:
        en_file.write(token)

    en_file.close()
    print(token)

def decodeFile(key):
    message= ''
    with open('content.txt', 'rb') as en_file:
        txt=en_file.read()
    try:
        message = key.decrypt(txt)
    except:
        print("Can't decode file")

    if  message != '':
        with open('message.txt', 'wb') as de_file:
            de_file.write(message)

        de_file.close()
        print(message)

questions = [
    {
        'type':'list',
        'name':'action',
        'message':'Select to encrypt or decrypt a file',
        'choices':[
            'encrypt',
            'decrypt',
        ]
    },
    {
        'type':'password',
        'name':'seed',
        'message':'enter the seed',
    },
    {
        'type':'password',
        'name':'password',
        'message':'enter the password',
    },

]

# key,f = encodingKey(seed='',password='')
# encodeFile(key)
#decodeFile(key)

answers = prompt(questions)
seed = answers['seed']
password = answers['password']
key,f = encodingKey(seed,password)
if answers['action'] == str('encrypt'):
    encodeFile(key)
else:
    decodeFile(key)
