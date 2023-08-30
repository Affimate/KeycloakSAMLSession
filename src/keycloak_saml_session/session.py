from OpenSSL import crypto
import base64
import json
from keycloak_saml_session import request

def format_pem_privatekey(key):
    """! Fonction permettant d'ajouter les entêtes
    nécéssaire au format PEM

    @param key clé privée sans les entêtes
    @return La clé privée avec les entêtes
    """
    return "-----BEGIN PRIVATE KEY-----\n"+key+"\n-----END PRIVATE KEY-----"


def load_privatekey(key):
    """! Fonction permettant de charger un clé privée

    @param key clé privée au format PEM
    @return Un objet représentant une clé privée
    """
    return crypto.load_privatekey(crypto.FILETYPE_PEM, format_pem_privatekey(key))


def sign_message(key, message, algo="sha256"):
    """! Fonction permettant de signer un message
    à partir d'une clé privée

    @param key clé privée chargée
    @param message message à signer
    @param algo Algorithme de signature
    @return Le message signé au format base64
    """
    sig = crypto.sign(key, message, algo)
    return base64.b64encode(sig)

class SessionManager:
    SESSION_EXIST = 100
    SESSION_NOT_EXIST = 101 
    def __init__(self, host, key, reaml):
        """! Fonction d'initialisation du SessionManager
        
        @param host Addresse KeyCloak
        @param key Clé privée
        @param reaml Reaml KeyCloak
        """
        self.host = host
        self.key = load_privatekey(key)
        self.reaml = reaml

    def check_session_status(self, application, id_session):
        """! Fonction permettant de checker le status d'un session
        lié à l'application

        @param application Nom de l'appllciation KeyCloak
        @param id_session Numéro de la session SAML
        @return True si le session existe, False sinon
        """
        message = {
	        "message": str(id_session)
        }
        data = json.dumps(message)
        signature = sign_message(self.key, "SessionMessage"+data)
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
