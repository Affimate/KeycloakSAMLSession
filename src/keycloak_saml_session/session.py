from OpenSSL import crypto
import base64
import json
from keycloak_saml_session import request

def format_pem_privatekey(key):
    return "-----BEGIN PRIVATE KEY-----\n"+key+"\n-----END PRIVATE KEY-----"


def load_privatekey(key):
    return crypto.load_privatekey(crypto.FILETYPE_PEM, format_pem_privatekey(key))


def sign_message(key, message, algo="sha256"):
    sig = crypto.sign(key, message, algo)
    return base64.b64encode(sig)

class SessionManager:
    SESSION_EXIST = 100
    SESSION_NOT_EXIST = 101 
    def __init__(self, host, key, reaml):
        self.host = host
        self.key = load_privatekey(key)
        self.reaml = reaml

    def check_session_status(self, application, id_session):
        message = {
	        "message": str(id_session)
        }
        data = json.dumps(message)
        signature = sign_message(self.key, data)
        addons = "" if self.host[-1] == "/" else "/"
        
        url = self.host + addons + "/realms/"+ self.reaml\
            +"/saml-session-manager/" + self.reaml + "/saml/" + application
        req = request.Request(url, "POST")
        req.addHeader("saml-signature-v1", signature)
        req.addBody(data, "application/json")
        
        if req.do_request():
            if req.get_json()["exists"]:
                return SessionManager.SESSION_EXIST
            else:
                return SessionManager.SESSION_NOT_EXIST
        else:
            return None