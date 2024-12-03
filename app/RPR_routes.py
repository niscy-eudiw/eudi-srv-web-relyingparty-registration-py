# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
This rpr_routes.py file is the blueprint of the Web RelyingParty Registration service.
"""

import base64
import binascii
from datetime import datetime, timedelta
import io
import json
import os
from uuid import uuid4
import uuid
import cbor2
from flask import (
    Blueprint,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
    jsonify,
)
import segno
import requests
from requests.auth import HTTPBasicAuth
import cbor2
import ssl

# from . import oidc_metadata
from pycose.messages import Sign1Message
from pycose.keys import CoseKey
from pycose.headers import Algorithm, KID
from pycose.algorithms import EdDSA
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from pycose.keys.keytype import KtyOKP
from pycose.keys.keyops import SignOp, VerifyOp
import base64
from binascii import unhexlify
from pycose.messages import Sign1Message
import cbor2
from pycose.keys import EC2Key, CoseKey

import urllib3

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import GeneralName, GeneralNames
from cryptography.x509 import SubjectAlternativeName
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from app.EJBCA_and_DB_func import func_get_user_id_by_hash_pid, generateCertificateRequest, get_certificate_data, getCertificateAuthorityName, getJsonBody, getTrustManagerOfCACertificate, http_post_requests_with_custom_ssl_context, update_status, user_relying_party_db
from requests_pkcs12 import Pkcs12Adapter
import urllib.parse

from app.validate_vp_token import validate_vp_token, cbor2elems
from app_config.config import ConfService as cfgserv

from app_config.EJBCA_config import EJBCA_Config as ejbca
from app_config.Crypto_Info import Crypto_Info as crypto
import models as db
import user as get_hash_user_pid
from app.data_management import oid4vp_requests,p12_temp, certificate_data_List

from app import logger

rpr = Blueprint("RPR", __name__, url_prefix="/")

rpr.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')


@rpr.route('/', methods=['GET','POST'])
def initial_page():

    return render_template('initial_page.html', redirect_url= cfgserv.service_url, pid_auth = cfgserv.service_url + "authentication", certificateList=cfgserv.service_url + "authentication_List")


@rpr.route("/authentication", methods=["GET","POST"])
def authentication():

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload ={
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "presentation_definition": {
            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "input_descriptors": [
            {
                "id": "eu.europa.ec.eudi.pid.1",
                "format": {
                "mso_mdoc": {
                    "alg": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "EdDSA"
                    ]
                }
                },
                "name": "EUDI PID",
                "purpose": "We need to verify your identity",
                "constraints": {
                "fields": [
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                    ],
                    "intent_to_retain": False
                    }
                ]
                }
            }
            ]
        }
        }


    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=json.dumps(payload)).json()

    QR_code_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
    )

    payload_sameDevice=payload
    session["session_id"]=str(uuid.uuid4())
    session["certificate_List"]=False

    payload_sameDevice.update({"wallet_response_redirect_uri_template":cfgserv.service_url +
                                                       "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session["session_id"]})

    response_same_device= requests.request("POST", url, headers=headers, data=json.dumps(payload_sameDevice)).json()

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_same_device["client_id"]
        + "&request_uri="
        + response_same_device["request_uri"]
    )

    oid4vp_requests.update({session["session_id"]:{"response": response_same_device, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})


    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(QR_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response["presentation_id"],
        redirect_url= cfgserv.service_url
    )
@rpr.route("/authentication_List", methods=["GET","POST"])
def authentication_List():

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload ={
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "presentation_definition": {
            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "input_descriptors": [
            {
                "id": "eu.europa.ec.eudi.pid.1",
                "format": {
                "mso_mdoc": {
                    "alg": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "EdDSA"
                    ]
                }
                },
                "name": "EUDI PID",
                "purpose": "We need to verify your identity",
                "constraints": {
                "fields": [
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                    ],
                    "intent_to_retain": False
                    }
                ]
                }
            }
            ]
        }
        }


    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=json.dumps(payload)).json()

    QR_code_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
    )

    payload_sameDevice=payload
    session["session_id"]=str(uuid.uuid4())
    session["certificate_List"]=True

    payload_sameDevice.update({"wallet_response_redirect_uri_template":cfgserv.service_url +
                                                       "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session["session_id"]})

    response_same_device= requests.request("POST", url, headers=headers, data=json.dumps(payload_sameDevice)).json()

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_same_device["client_id"]
        + "&request_uri="
        + response_same_device["request_uri"]
    )

    oid4vp_requests.update({session["session_id"]:{"response": response_same_device, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry), "certificate_List":True}})


    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(QR_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response["presentation_id"],
        redirect_url= cfgserv.service_url
    )

@rpr.route("/pid_authorization")
def pid_authorization_get():

    presentation_id= request.args.get("presentation_id")

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}),200
            
    
@rpr.route("/getpidoid4vp", methods=["GET", "POST"])
def getpidoid4vp():

    if "response_code" in request.args and "session_id" in request.args:

        response_code = request.args.get("response_code")
        presentation_id = oid4vp_requests[request.args.get("session_id")]["response"]["presentation_id"]
        session["session_id"]=request.args.get("session_id")
        if oid4vp_requests[request.args.get("session_id")]["certificate_List"] !=None:
            session["certificate_List"]=True
        url = (
            "https://dev.verifier-backend.eudiw.dev/ui/presentations/"
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code=" + response_code
        )

    elif "presentation_id" in request.args:
        presentation_id = request.args.get("presentation_id")
        url = "https://dev.verifier-backend.eudiw.dev/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="

    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),400
    
    error, error_msg= validate_vp_token(response.json())

    if error == True:
        return error_msg
    
    mdoc_json = cbor2elems(response.json()["vp_token"][0] + "==")

    attributesForm={}

    for doctype in mdoc_json:
        for attribute, value in mdoc_json[doctype]:
            attributesForm.update({attribute:value})

    temp_user_id=str(uuid.uuid4())
    session[temp_user_id]= attributesForm

    if session["certificate_List"]== True:
        return certificate_List(temp_user_id)

    attributesForm={}

    form_items={
        "Country": "select",
        "Name": "string",
        "Common Name": "string",
        "Registration Number": "string",
        "Contact": "contact",
        "Intended use of European Digital Identity Wallets": "text_area",
        "DNS Name":"string",
        "Password":"password"
    }
    descriptions = {
        "Country": "Country in which the relying party is established.",
        "Name": "Name of the relying party as stated in an official record.",
        "Common Name": "Common Name of the Relying Party, in a format suitable for presenting to an end-user.",
        "Registration Number": "Registration number as stated in an official record together with identification data of that official record.",
        "Contact": "Contact details (address, e-mail and phone number) of the relying party.",
        "Intended use of European Digital Identity Wallets": "Intended use of European Digital Identity Wallets, including an indication of the data to be requested by the relying party from users.",
        "DNS Name":"DNS Name to add to the certificate.",
        "Password":"Password required for P12 file. "
    }


    attributesForm.update(form_items)
    

    return render_template("dynamic-form.html", desc = descriptions, countries = ejbca.countries ,attributes=attributesForm,temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "relying_party_registration_request")

@rpr.route("/relying_party_registration_request", methods=["GET", "POST"])
def relying_party_registration():

    modulus=crypto.key_size
    exponent=crypto.exponent
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend() )

    temp_user_id=request.form.get("temp_user_id")

    user=session[temp_user_id]
    givenName=user["given_name"]
    surname=user["family_name"]

    commonName=request.form.get("Common Name")
    countryName=request.form.get("Country")
    organizationName=request.form.get("Name")
    registration_number=request.form.get("Registration Number")
    email=request.form.get("email")
    dns_Name=request.form.get("DNS Name")
    password=request.form.get("Password")


    certificateRequest= generateCertificateRequest(priv_key, commonName, countryName, organizationName, registration_number, email,dns_Name)
    
    certificateRequestString = "-----BEGIN CERTIFICATE REQUEST-----\n"+ base64.b64encode(certificateRequest).decode("utf-8") + "\n"+ "-----END CERTIFICATE REQUEST-----"
    certificateAuthorityName = getCertificateAuthorityName(countryName)
    certificateRequestBody = getJsonBody(certificateRequestString, certificateAuthorityName)
    postUrl = "https://" + ejbca.cahost + "/ejbca/ejbca-rest-api/v1" + ejbca.endpoint

    headers ={
        "Content-Type": "application/json",
        'Authorization': 'Bearer test',
    }

    clientP12ArchiveFilepath = ejbca.clientP12ArchiveFilepath
    clientP12ArchivePassword = ejbca.clientP12ArchivePassword
    ManagementCA = ejbca.managementCA

    trustCA= getTrustManagerOfCACertificate(ManagementCA)

    response = http_post_requests_with_custom_ssl_context(ManagementCA, clientP12ArchiveFilepath, clientP12ArchivePassword, postUrl,certificateRequestBody, headers)

    response = response.json()
    
    certificate_bytes=base64.b64decode(response["certificate"])

    certificate = x509.load_der_x509_certificate(certificate_bytes, default_backend())

    serial_number=response["serial_number"]

    user_relying_party_db(user,request.form, serial_number, certificate,response["certificate"], session["session_id"])

    p12=pkcs12.serialize_key_and_certificates(
        name=commonName.encode("utf-8"),key=priv_key,cert=certificate, cas=list().append(trustCA),
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    tag = uuid.uuid4()

    file_name = commonName + "_" + str(tag)

    p12_temp.update({file_name:{"response": p12, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})

    cert = certificate.subject.rfc4514_string().split(",")
    dic = {parte.split("=")[0]: parte for parte in cert}
    order = [dic.get("C"), dic.get("O"), dic.get("CN")]
    aux = [v for k, v in dic.items() if k not in ["C", "O", "CN"]]

    cert_subject_rfc4514_string = ",".join(order + aux)

    certificate_presentation={
        "certificate_issuer":certificate.issuer.rfc4514_string(),
        "certificate_distinguished_name":cert_subject_rfc4514_string,
        "validity_from":certificate.not_valid_before_utc,
        "validity_to":certificate.not_valid_after_utc,
    }

    return render_template('downloadPage.html', attributes=certificate_presentation, download_url= "/Download/"+ file_name)

@rpr.route("/Download/<name>", methods=["GET", "POST"])
def download(name):

    p12_file_bytes=p12_temp[name]["response"]

    final_name = name.split("_")[0] + ".p12"
    print(final_name)
    
    extra = {'code': session["session_id"]} 
    logger.info(f"Download p12.", extra=extra)

    return send_file(io.BytesIO(p12_file_bytes),download_name=final_name,as_attachment=True)

def certificate_List(temp_user_id):

    user=session[temp_user_id]

    givenName=user["given_name"]
    surname=user["family_name"]
    birth_date=user["birth_date"]
    issuing_country=user["issuing_country"]
    issuance_authority=user["issuing_authority"]

    new_user = get_hash_user_pid.User(surname, givenName, birth_date, issuing_country, issuance_authority)
    hash_pid = new_user.hash

    user_id=func_get_user_id_by_hash_pid(hash_pid, session["session_id"])

    certificate_data= get_certificate_data(user_id, session["session_id"])

    certificate_data_List.update({temp_user_id:{"certificate_data": certificate_data, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})

    return render_template('CertificateList.html', certificates=certificate_data, log_id = session["session_id"], redirect_url= cfgserv.service_url, user_id=temp_user_id)


@rpr.route("/Revoke", methods=["GET", "POST"])
def Revoke_Certificate():

    certificate= request.args.get("id")

    user_id=request.args.get("user_id")

    log_id = request.args.get("log_id")

    certificate_data=certificate_data_List[user_id]["certificate_data"]

    cn_issuer=certificate_data[certificate]["certificate_issuer"]

    serial_number=certificate_data[certificate]["serial_number"]


    revocation_status_Url = "https://" + ejbca.cahost + "/ejbca/ejbca-rest-api/v1/certificate/"+ urllib.parse.quote(cn_issuer) +"/" + serial_number + "/revocationstatus"

    revocation_Url = "https://" + ejbca.cahost + "/ejbca/ejbca-rest-api/v1/certificate/"+ urllib.parse.quote(cn_issuer) +"/" + serial_number + "/revoke?reason=KEY_COMPROMISE"

    headers ={
        "Content-Type": "application/json",
        'Authorization': 'Bearer test',
    }

    clientP12ArchiveFilepath = ejbca.clientP12ArchiveFilepath
    clientP12ArchivePassword = ejbca.clientP12ArchivePassword

    session = requests.Session()
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=clientP12ArchiveFilepath, pkcs12_password=clientP12ArchivePassword))

    response_status = session.get(revocation_status_Url, headers=headers, verify=False)

    response_s=response_status.json()

    if response_status.status_code !=200:
        #response_s["error_message"]

        return jsonify({"error": "Error Revoking"}),500

    if response_s["revoked"]==True:

        update_status(certificate_data[certificate]["accessCertificate_id"], log_id)

        data = {"message": "Sucess"}
        return jsonify({"message": data}),200

    else:

        response_revoke = session.put(revocation_Url, headers=headers, verify=False)

        response_r=response_revoke.json()
        
        if response_revoke.status_code !=200:
            return jsonify({"error":"Error Revoking"}),500
        
        if response_r["revoked"]==True:

            try:

                update_status(certificate_data[certificate]["accessCertificate_id"], log_id)
                data = {"message": "Sucess"}

                return jsonify({"message": data}),200
            
            except:
                extra = {'code':log_id} 
                logger.error(f"Error Revoking", extra=extra)
                return jsonify({"error": "Error Revoking"}),500
        else:
            extra = {'code':log_id} 
            logger.error(f"Error Revoking", extra=extra)
            return jsonify({"error": "Error Revoking"}),500

@rpr.route("/Logout", methods=["GET", "POST"])
def Logout():

    extra = {'code':session["session_id"]} 
    logger.info(f"Logout", extra=extra)
    session.clear()

    return render_template('initial_page.html', redirect_url= cfgserv.service_url, pid_auth = cfgserv.service_url + "authentication", certificateList=cfgserv.service_url + "authentication_List")
