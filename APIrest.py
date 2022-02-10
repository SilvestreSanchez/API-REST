#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

from flask import Flask,request
from flask_restful import Resource,Api,reqparse
import json
import hashlib
import os
from base64 import b64encode,b64decode
import linecache
from uuid import uuid4
from datetime import datetime

# ----- DECLARACION VARIABLES GLOBALES -----

SHADOW_FILE = "shadow"
USERS_DIR= "users"
VERSION = "1.0"
HASHING = "5"
RANDOM_SALT=""
EXPIRATION_TIME = 300 #seconds
FORBIDDEN_CHAR= "¡!|@#$%^&*()+?=,;<>/\[] "

app = Flask(__name__)
api = Api(app)
parser=reqparse.RequestParser()
parser.add_argument('username',required=True)
parser.add_argument('password',required=True)

parserDocs=reqparse.RequestParser()
parserDocs.add_argument('doc_content',required=True)

_users_tokens_={}




# ----- INICIALIZACION -----
        
def __init__():
        if not os.path.exists(USERS_DIR):
                try:
                        os.mkdir(USERS_DIR)
                except OSError:
                        print("Error creando el directorio %s" % USERS_DIR)
                        return -1
                
        if not os.path.exists(SHADOW_FILE):
                file=open(SHADOW_FILE,"w")
                file.close()
                
# ----- FUNCIONES AUXILIARES -----

def get_hashed_password(plain_text_password,salt):
        if(salt== RANDOM_SALT):
                salt_encoded = os.urandom(32)       
        else:
                salt_encoded=b64decode(salt)
                
        salt_str=b64encode(salt_encoded).decode('utf-8')
        pass_encoded = plain_text_password.encode() + salt_encoded
        final_hash= hashlib.sha256(pass_encoded).hexdigest()
        return salt_str,final_hash

def check_password(plain_text_password, hashed_password,salt):
        chk_pass=get_hashed_password(plain_text_password,salt)[1]
        return bool(chk_pass==hashed_password)
        
def exists(usr):
        with open(SHADOW_FILE) as fp:
                line= fp.readline()
                line_counter=1
                while line:
                        pos=line.find(":")
                        if(pos!=-1):
                                user_compare= line[0:pos]
                                if(user_compare==usr):
                                        return True,line_counter
                        line= fp.readline()
                        line_counter+=1
                return False,-1
                        

def genToken(user):
        token=str(uuid4())
        expedition_time=datetime.now()
        _users_tokens_[user]=token,expedition_time
        return token


def checkToken(user):
        if user in _users_tokens_:
                exp_date=_users_tokens_[user][1]
                current_date=datetime.now()
                delta= current_date - exp_date
                if(delta.seconds>=EXPIRATION_TIME):
                        return False
                else:
                        return True
        else: # este else es por si el server se reincia y no estan cargadas los tokens en memoria, que tome el token como caducado
                return False


def getToken(user):
        if user in _users_tokens_:
                
                return _users_tokens_[user][0]
        else:
                return None

def submitUser(user, password):
        salt,hashed_pass=get_hashed_password(password,RANDOM_SALT)
        str= user + ":$" + HASHING + "$" + salt +"$"+hashed_pass
        file=open(SHADOW_FILE,"a")
        file.write(str + "\n")
        file.close()
        os.mkdir(USERS_DIR + "/" + user)

def validate(user,plain_passw,n_line):
        user_line=linecache.getline(SHADOW_FILE,n_line)
        i=0
        offset=0
        while i<3:
                x=user_line.find("$",offset)
                if i<2:
                        offset=x+1
                i+=1

        salt= user_line[offset:x]
        hashed_pass= user_line[x+1:].strip('\n')
        if(check_password(plain_passw,hashed_pass,salt)==True):
                return True
        else:
                return False



        
def checkPet(username,doc_id):
        if any(c in FORBIDDEN_CHAR for c in doc_id):
                        return "El documento no puede contener caracteres especiales",400
                
        auth=request.headers.get('Authorization')
        if auth is not None: #si no, falta header
                type,token=auth.split()
                if(exists(username)[0]==True): #si no, user not found
                        if (type=="token"): #si no, auth bad type
                                saved_token=getToken(username)
                                if saved_token is None:
                                        return "Token incorrecto",401
                                if (saved_token==token): #si no, error en token
                                        if(checkToken(username)==True):#si no, token caducado
                                                return True
                                        else:
                                                return "Token caducado",401
                                else:
                                        return "Token incorrecto",401
                        else:
                                return "Error en el tipo de Authorization",400
                else:
                        return "Directorio de usuario no encontrado",404
        else:
                return "Falta cabecera Authorization",400
                                                
                                        
def fileExists(path):
        return os.path.exists(path)

def wrFile(path,content):
        with open(path, 'w') as outfile:
                json.dump(content, outfile)
                return outfile.tell()

def get_allDocs(user):
        allDocs={}
        path=USERS_DIR +"/"+user
        contenido= os.listdir(path)
        if len(contenido) > 0:
                
                for doc in contenido:
                        doc_path= path + "/" + doc
                        with open(doc_path) as jf:
                                data=json.load(jf)
                                allDocs[doc]=data
                return allDocs
        else:
                return None




def isJson(doc):
        try:
                y=doc.split(".")
                if len(y) == 2 and y[1] == "json":
                        return True
        except:
                return False
        return False


# ---- OBJETOS Y VERBOS -----

class Version(Resource):
        def get(self):
                return "Version: "+VERSION
        
class Signup(Resource):
        def post(self):
                args= parser.parse_args()
                user=args['username']
                passw=args['password']
                if len(user) < 4 or len(user) > 20:
                        return "El nombre de usuario debe estar entre 4 y 20 caracteres",400
                if any(c in FORBIDDEN_CHAR for c in user):
                        return "El nombre de usuario no puede contener caracteres especiales",400
                
                if len(passw) < 8 or len(passw) > 25:
                        return "La contrasena debe tener entre 8 y 25 caracteres",400
                if not any(c.isupper() for c in passw) or not any(c.islower() for c in passw) or not any(c.isdigit() for c in passw):
                        return "La contrasena debe contener mayusculas, minisculas y numeros",400
                if (exists(user)[0]==False):
                        submitUser(user,passw)
                        return {"access_token": genToken(user)}
                else:
                        return "Nombre de usuario en uso",409

                
class Login(Resource):
        def post(self):
                args=parser.parse_args()
                user=args['username']
                passw=args['password']
                exist,line=exists(user)
                if(exist==True):
                        if(validate(user,passw,line)==True):
                                if(checkToken(user)==True):
                                        tok_return=getToken(user)
                                else:
                                        tok_return=genToken(user)
                                                
                                return {"access_token": tok_return}
                        else:
                                return "Usuario y/o contrasena incorrectos", 401
                else:
                        return "Usuario y/o contrasena incorrectos", 401
                                

class FileManager(Resource):
        def get(self,username,doc_id):
                valid=checkPet(username,doc_id)
                if(valid==True):
                        if(doc_id== "_all_docs"):
                                getter=get_allDocs(username)
                                if(getter is not None):
                                        return getter
                                else:
                                        return "No se han encontrado archivos en el directorio del usuario",404
                        path=USERS_DIR + "/" + username + "/" + doc_id
                        if fileExists(path): # si no error, no existe
                                #existe, return file
                                with open(path) as jf:
                                        data=json.load(jf)
                                        return data
                        else:
                                return "Archivo no encontrado",404
                else:
                        return valid
                                
        def post(self,username,doc_id):
                valid=checkPet(username,doc_id)
                if(valid==True):
                        path=USERS_DIR + "/" + username + "/" + doc_id
                        if not fileExists(path): # si no error, ya existe
                                if (isJson(doc_id)==False):
                                        return "Introduzca un archivo json correcto",400
                                args=parserDocs.parse_args()
                                doc_content=args['doc_content']
                                bytes_wr=wrFile(path,doc_content)
                                return {"size": bytes_wr}
                        else:
                                return "El archivo ya existe",403
                else:
                        return valid
                
        def put(self,username,doc_id):
                valid=checkPet(username,doc_id)
                if(valid==True):
                        path=USERS_DIR + "/" + username + "/" + doc_id
                        if fileExists(path): # si no error, no existe y no se puede actualizar
                                args=parserDocs.parse_args()
                                doc_content=args['doc_content']
                                os.remove(path)
                                bytes_wr=wrFile(path,doc_content)
                                return {"size": bytes_wr}
                        else:
                                return "El archivo no se encuentra, no se puede actualizar",404
                else:
                        return valid
                        
                
        def delete(self,username,doc_id):
                valid=checkPet(username,doc_id)
                if(valid==True):
                        path=USERS_DIR + "/" + username + "/" + doc_id
                        if fileExists(path): # si no error, no existe y no se puede borrar
                                os.remove(path)
                                return {}
                        else:
                                return "Archivo no encontrado",404
                else:
                        return valid
        


                
api.add_resource(Version,'/version')
api.add_resource(Signup,'/signup')
api.add_resource(Login,'/login')
api.add_resource(FileManager,'/<string:username>/<string:doc_id>')


if __name__ == '__main__':
    __init__()
    app.run(debug=True,ssl_context=('cert.pem','key.pem'))
