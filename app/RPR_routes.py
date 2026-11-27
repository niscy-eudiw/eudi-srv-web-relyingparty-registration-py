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

import ast
import base64
import binascii
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import io
import json
import os
import re
import time
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
    send_from_directory,
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
from pycose.algorithms import EdDSA, Es256
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from pycose.keys.keytype import KtyOKP
from pycose.keys.keyops import SignOp, VerifyOp
import base64
from binascii import unhexlify
from pycose.messages import Sign1Message
import cbor2
from pycose.keys import EC2Key, CoseKey
from cryptojwt.jws.jws import JWS
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import import_private_ec_key_from_file

import urllib3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import GeneralName, GeneralNames
from cryptography.x509 import SubjectAlternativeName
from cryptography.hazmat.primitives.asymmetric import ec, utils
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
from flask import send_from_directory

rpr = Blueprint("RPR", __name__, url_prefix="/")

rpr.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

def validate_required_fields(data, required_fields):
    missing = []

    for field in required_fields:
        if field not in data:
            missing.append(field)
            continue

        value = data[field]

        if value is None:
            missing.append(field)
            continue

        # empty strings
        if isinstance(value, str) and value.strip() == "":
            missing.append(field)
            continue

        # lists ou empty dicts
        if isinstance(value, (list, dict)) and len(value) == 0:
            missing.append(field)
            continue

    return missing

def is_int(value):
    # bool is a subclass of int, so reject it explicitly
    return isinstance(value, int) and not isinstance(value, bool)

def is_id(value):
    return is_int(value) and value > 0

def is_str(value):
    return isinstance(value, str)

def is_non_blank_str(value):
    return isinstance(value, str) and value.strip() != ""

def is_list_of(value, check):
    return isinstance(value, list) and all(check(item) for item in value)

TYPE_NAMES = {str: "a string", int: "an integer", bool: "a boolean", list: "an array", dict: "an object"}

def check_field_types(item, types):
    for field, expected in types.items():
        value = item.get(field)
        if value is None:
            continue
        valid = is_int(value) if expected is int else isinstance(value, expected)
        if not valid:
            return error_invalid(f"Field '{field}' must be {TYPE_NAMES[expected]}.")
    return None

def error_response(message, missing_fields=None, code=400):
    return {
        "status": "error",
        "code": code,
        "message": message,
        "data": {
            "missing_fields": missing_fields or []
        }
    }, code

def error_invalid(message, code=400):
    return {
        "status": "error",
        "code": code,
        "message": message
    }, code

def update_response(message, len, code=201):
    return {
        "status": "success",
        "code": code,
        "message": message,
        "updated_count": len
    }, code

def create_response(message, data=None, result=None, code=201):
    return {
        "status": "success",
        "code": code,
        "message": message,
        "data": {
            data: result or []
        }
    }, code

def list_response(message, result, name, code=200):
    return {
        "status": "success",
        "code": code,
        "message": message,
        "data": {
            name: result
        }
    }, code

@rpr.route("/swagger/api.yaml")
def swagger_yaml():
    return send_from_directory("swagger", "api.yaml")

def serialize_json(value):
    return json.dumps(value) if value is not None else None

def deserialize_json(value):
    return json.loads(value) if value else None

def validate_date_field(value, field_name):
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except (ValueError, TypeError):
        return error_response(
            f"Invalid '{field_name}'. Expected format: YYYY-MM-DD."
        )
    return None

@rpr.route('/', methods=['GET','POST'])
def initial_page():

    return render_template('initial_page.html', redirect_url= cfgserv.service_url, pid_auth = cfgserv.service_url + "authentication")


@rpr.route("/authentication", methods=["GET"])
def authentication():

    payload ={
      "type": "vp_token",
      "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
      "intended_use_id": "TEST-01",
      "dcql_query": {
          "credentials": [
          {
              "id": "query_0",
              "format": "mso_mdoc",
              "meta": {
              "doctype_value": "eu.europa.ec.eudi.pid.1"
              },
              "claims": [
              {
                  "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "family_name"
                  ],
                  "intent_to_retain": False
              },
              {
                  "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "given_name"
                  ],
                  "intent_to_retain": False
              },
              {
                  "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "birth_date"
                  ],
                  "intent_to_retain": False
              },
              {
                  "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "issuing_authority"
                  ],
                  "intent_to_retain": False
              },
              {
                  "path": [
                  "eu.europa.ec.eudi.pid.1",
                  "issuing_country"
                  ],
                  "intent_to_retain": False
              }
              ]
          }
          ]
      }
    }


    headers = {
        "Content-Type": "application/json",
    }

    url = "https://" + cfgserv.url_verifier +"/ui/presentations"
    
    response = requests.request("POST", url, headers=headers, data=json.dumps(payload)).json()
    

    QR_code_url = (
        "eudi-openid4vp://" + cfgserv.url_verifier + "?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
        + "&request_uri_method="
        + response["request_uri_method"]
    )

    
    session["session_id"]=str(uuid.uuid4())
    session["certificate_List"]=False

    qrcode = segno.make(QR_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return_json = {
        "QR_code_url": QR_code_url,
        "presentation_id": response["transaction_id"]
    }

    return (return_json)

@rpr.route("/pid_authorization", methods=["GET"])
def pid_authorization_get():

    presentation_id= request.args.get("presentation_id")

    url = "https://" + cfgserv.url_verifier+ "/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
    
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
            
    
@rpr.route("/getpidoid4vp", methods=["POST"])
def getpidoid4vp():
    if "presentation_id" not in request.args:
        return {
            "status": "error",
            "code": 400,
            "message": "Missing presentation_id"
        }, 400
    else:
        presentation_id = request.args.get("presentation_id")
          
        url = "https://" + cfgserv.url_verifier +"/ui/presentations/" + presentation_id 
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

    mdoc_json = cbor2elems(response.json()["vp_token"]["query_0"][0] + "==")

    attributesForm={}

    for doctype in mdoc_json:
        for attribute, value in mdoc_json[doctype]:
            attributesForm.update({attribute:value})

    user = attributesForm

    givenName=user["given_name"]
    surname=user["family_name"]
    birth_date=user["birth_date"]
    issuing_country=user["issuing_country"]
    issuance_authority=user["issuing_authority"]

    new_user = get_hash_user_pid.User(surname, givenName, birth_date, issuing_country, issuance_authority)
    hash_pid = new_user.hash

    check_user = db.check_user(hash_pid)
    
    if(check_user == None):
        db.insert_user(hash_pid)
        return (hash_pid)
    else:
        return (hash_pid)

## -law
@rpr.route('/law/create', methods=['POST'])
def create_law():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "law"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    laws = data.get("law", [])

    if not isinstance(laws, list):
        return error_invalid("Field 'law' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    for law in laws:
        if not isinstance(law, dict):
            return error_invalid("Each law must be an object.")

        missing = validate_required_fields(law, ["legislativeIdentifier"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(law, {"legislativeIdentifier": str})
        if error:
            return error

        if not is_list_of(law.get("legalBasis") or [], is_non_blank_str):
            return error_invalid("Field 'legalBasis' must be an array of non-empty strings.")

        law["legalBasis"] = [value.strip() for value in law.get("legalBasis") or []]

    try:
        with db.transaction() as cursor:
            for law in laws:
                legislativeIdentifier = law.get("legislativeIdentifier")
                legalBasis = law.get("legalBasis") or []

                law_id = db.insert_law(legislativeIdentifier, user_id, cursor=cursor)
                result.append(law_id)

                for aux in legalBasis:
                    db.insert_law_legal_basis(law_id, aux, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Law created successfully", "Law ids", result)

@rpr.route('/law/list', methods=['POST'])
def list_law():

    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid", missing)

    result = db.get_law(user_id)

    return list_response("Law retrieved successfully.", result, "law")

## -legal person 
@rpr.route('/legal_person/create', methods=['POST'])
def create_legal_person():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legalPerson"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    legalPersons = data.get("legalPerson", [])

    if not isinstance(legalPersons, list):
        return error_invalid("Field 'legalPerson' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    result = []

    to_insert = []

    #verification
    for legalPerson in legalPersons:

        if not isinstance(legalPerson, dict):
            return error_invalid(
                "Each legalPerson must be an object."
            )

        missing = validate_required_fields(
            legalPerson,
            ["legalName"]
        )

        if missing:
            return error_response(
                "Missing required fields.",
                missing
            )

        legal_names = legalPerson.get("legalName", [])

        if not isinstance(legal_names, list):
            return error_invalid(
                "legalName must be a list."
            )

        if not legal_names:
            return error_invalid(
                "legalName must contain at least one name."
            )

        clean_legal_names = []

        for legal_name in legal_names:

            if not isinstance(legal_name, str):
                return error_invalid(
                    "Each legalName must be a string."
                )

            legal_name = legal_name.strip()

            if not legal_name:
                return error_invalid(
                    "legalName cannot be empty or contain only whitespace."
                )

            clean_legal_names.append(legal_name)

        laws = legalPerson.get("law") or []

        if not is_list_of(laws, is_id):
            return error_invalid("Field 'law' must be an array of positive integers.")

        for law in laws:
            if user_id != db.check_law(law):
                return error_invalid(
                    f"law id {law} doesn't belong to this user"
                )

        to_insert.append({"legalNames": clean_legal_names, "laws": laws})

    #inserts data base
    try:
        with db.transaction() as cursor:
            for legalPerson in to_insert:
                legal_person_id = db.insert_legal_person(user_id, cursor=cursor)
                result.append(legal_person_id)

                for legalName in legalPerson["legalNames"]:
                    db.insert_legal_person_name(legal_person_id, legalName, cursor=cursor)

                for law in legalPerson["laws"]:
                    db.associate_legal_person_law(legal_person_id, law, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Legal Person created successfully", "Legal Person ids", result)

@rpr.route('/legal_person/list', methods=['POST'])
def list_legal_person():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_legal_person(user_id)

    return list_response("Legal Persons retrieved successfully.", result, "legal_person")

@rpr.route('/legal_person/update_law', methods=['POST'])
def update_legal_person_law():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legal_person_id", "law_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    legal_person_id = data.get("legal_person_id")
    law_ids = data.get("law_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_legal_person(legal_person_id):
        return error_invalid(f"Legal Person id {legal_person_id} doesn't belong to this user")
    
    for law_id in law_ids:
        if user_id != db.check_law(law_id):
            return error_invalid(f"law id {law_id} doesn't belong to this user")
        
    #insert data base
    for law_id in law_ids:
        db.insert_legal_person_law(legal_person_id, law_id)

    return update_response("Legal person law associations updated successfully", len(law_ids))

@rpr.route('/legal_person/remove_law', methods=['POST'])
def remove_legal_person_law():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legal_person_id", "law_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    legal_person_id = data.get("legal_person_id")
    law_ids = data.get("law_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    # verification
    if user_id != db.check_legal_person(legal_person_id):
        return error_invalid(f"Legal Person id {legal_person_id} doesn't belong to this user")
    
    for law_id in law_ids:
        if user_id != db.check_law(law_id):
            return error_invalid(f"law id {law_id} doesn't belong to this user")
        
    deleted_count = db.delete_legal_person_laws(legal_person_id, law_ids)

    return update_response(
        "Legal person law associations removed successfully",
        deleted_count
    )

## -natural person
@rpr.route('/natural_person/create', methods=['POST'])
def create_natural_person():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "naturalPerson"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    naturalPersons = data.get("naturalPerson", [])

    if not isinstance(naturalPersons, list):
        return error_invalid("Field 'naturalPerson' must be an array.")

    user_id = db.check_user(hash_pid)
    result = []

    if user_id is None:
        return error_invalid("Invalid hash_pid")

    #verification
    for naturalPerson in naturalPersons:
        if not isinstance(naturalPerson, dict):
            return error_invalid("Each naturalPerson must be an object.")

        missing = validate_required_fields(naturalPerson, ["familyName", "givenName"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(
            naturalPerson,
            {"familyName": str, "givenName": str, "dateOfBirth": str, "placeOfBirth": str}
        )
        if error:
            return error

    #insert data base
    try:
        with db.transaction() as cursor:
            for naturalPerson in naturalPersons:
                family_name = naturalPerson.get("familyName")
                given_name = naturalPerson.get("givenName")
                date_of_birth = naturalPerson.get("dateOfBirth")
                place_of_birth = naturalPerson.get("placeOfBirth")

                natural_person_id = db.insert_natural_person(family_name, given_name, date_of_birth, place_of_birth, user_id, cursor=cursor)
                result.append(natural_person_id)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Natural Person created successfully", "Natural Person ids", result)

@rpr.route('/natural_person/list', methods=['POST'])
def get_natural_person():

    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_natural_person(user_id)

    return list_response("Natural Persons retrieved successfully.", result, "natural_person")

## -identifier
@rpr.route('/identifier/create', methods=['POST'])
def create_identifier():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "identifier"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    identifiers = data.get("identifier", [])

    if not isinstance(identifiers, list):
        return error_invalid("Field 'identifier' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #verification
    for identifier in identifiers:
        if not isinstance(identifier, dict):
            return error_invalid("Each identifier must be an object.")

        missing = validate_required_fields(identifier, ["identifier", "type"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(identifier, {"identifier": str, "type": str})
        if error:
            return error

        type = identifier.get("type")
        if type not in cfgserv.legal_entity_type_identifier["Type of Identifier"]:
            return error_invalid(f"Invalid type_of_identifier. Must be one of: {', '.join(cfgserv.legal_entity_type_identifier['Type of Identifier'])}")

    #insert data base
    try:
        with db.transaction() as cursor:
            for identifier in identifiers:
                identifier_value = identifier.get("identifier")
                type = identifier.get("type")

                identifier_id = db.insert_identifier(identifier_value, type, user_id, cursor=cursor)
                result.append(identifier_id)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Identifier created successfully", "Identifier ids", result)

@rpr.route('/identifier/list', methods=['POST'])
def list_identifier():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_identifier(user_id)

    return list_response("Identifiers retrieved successfully.", result, "identifier")

## -legal entity
@rpr.route('/legal_entity/create', methods=['POST'])
def create_legal_entity():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legal_entity"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    legal_entity = data.get("legal_entity")

    if not isinstance(legal_entity, list):
        return error_invalid("Field 'legal_entity' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #verification
    for aux in legal_entity:
        if not isinstance(aux, dict):
            return error_invalid("Each legal_entity must be an object.")

        missing = validate_required_fields(aux, ["identifiers", "country"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(aux, {"legal_person_id": int, "natural_person_id": int, "country": str})
        if error:
            return error

        for field in ("legal_person_id", "natural_person_id"):
            if aux.get(field) is not None and not is_id(aux[field]):
                return error_invalid(f"Field '{field}' must be a positive integer.")

        if not is_list_of(aux["identifiers"], is_id):
            return error_invalid("Field 'identifiers' must be an array of positive integers.")

        for field in ("postalAddress", "email", "phone", "infoURI"):
            if not is_list_of(aux.get(field) or [], is_non_blank_str):
                return error_invalid(f"Field '{field}' must be an array of non-empty strings.")

            aux[field] = [value.strip() for value in aux.get(field) or []]

        legal_person_id = aux.get("legal_person_id")
        natural_person_id = aux.get("natural_person_id")
        identifier_ids = aux["identifiers"]
        country = aux.get("country")

        if legal_person_id and natural_person_id:
            return error_response("There can't be two different types of people", "legal_person_id or natural_person_id")
        if not legal_person_id and not natural_person_id:
            return error_response("Missing required fields.", "legal_person_id or natural_person_id")

        if country not in cfgserv.eu_countries:
                return error_invalid(f"Invalid Country. Must be one of: {', '.join(cfgserv.eu_countries)}")

        if natural_person_id:
            if user_id != db.check_natural_person(natural_person_id):
                return error_invalid(f"The natural person ID {natural_person_id} does not belong to this user")

        if legal_person_id: 
            if user_id != db.check_legal_person(legal_person_id):
                return error_invalid(f"The legal person ID {legal_person_id} does not belong to this user")
        
        for identifier_id in identifier_ids:
            if user_id != db.check_identifier(identifier_id):
                return error_invalid(f"The identifier ID {identifier_id} does not belong to this user")

    #insert data base
    try:
        with db.transaction() as cursor:
            for aux in legal_entity:
                identifier_ids = aux["identifiers"]
                postalAddress = aux.get("postalAddress") or []
                country = aux.get("country")
                emails = aux.get("email") or []
                phones = aux.get("phone") or []
                infoURIs = aux.get("infoURI") or []
                legal_person_id = aux.get("legal_person_id")
                natural_person_id = aux.get("natural_person_id")

                legal_entity_id = db.insert_legal_entity(legal_person_id, natural_person_id, country, user_id, cursor=cursor)
                result.append(legal_entity_id)

                for identifier_id in identifier_ids:
                    db.insert_legal_entity_identifier(legal_entity_id, identifier_id, cursor=cursor)

                for address in postalAddress:
                    db.insert_legal_entity_postal_address(legal_entity_id, address, cursor=cursor)

                for email in emails:
                    db.insert_legal_entity_email(legal_entity_id, email, cursor=cursor)

                for phone in phones:
                    db.insert_legal_entity_phone(legal_entity_id, phone, cursor=cursor)

                for infoURI in infoURIs:
                    db.insert_legal_entity_info_uri(legal_entity_id, infoURI, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Legal Entity created successfully.", "Legal Entity ids", result)

@rpr.route('/legal_entity/list', methods=['POST'])
def list_legal_entity():

    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_legal_entity(user_id)

    return list_response("Legal Entity retrieved successfully.", result, "legal_entity")

@rpr.route('/legal_entity/update_identifier', methods=['POST'])
def update_legal_entity_identifier():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legal_entity_id", "identifier_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    legal_entity_id = data.get("legal_entity_id")
    identifier_ids = data.get("identifier_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_legal_entity(legal_entity_id):
        return error_invalid(f"Legal Entity id {legal_entity_id} doesn't belong to this user")
    
    for identifier_id in identifier_ids:
        if user_id != db.check_identifier(identifier_id):
            return error_invalid(f"Identifier id {identifier_id} doesn't belong to this user")
        
    #insert data base
    for identifier_id in identifier_ids:
        db.insert_legal_entity_identifier(legal_entity_id, identifier_id)

    return update_response("Legal Entity Identifier associations updated successfully", len(identifier_ids))

@rpr.route('/legal_entity/remove_identifier', methods=['POST'])
def remove_legal_entity_remove_identifier():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "legal_entity_id", "identifier_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    legal_entity_id = data.get("legal_entity_id")
    identifier_ids = data.get("identifier_ids", [])

    #verification
    if not isinstance(identifier_ids, list) or not identifier_ids:
        return error_invalid("identifier_ids must be a non-empty list")

    identifier_ids = list(set(identifier_ids))
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    if user_id != db.check_legal_entity(legal_entity_id):
        return error_invalid(f"Legal Entity id {legal_entity_id} doesn't belong to this user")
     
    for identifier_id in identifier_ids:
        if user_id != db.check_identifier(identifier_id):
            return error_invalid(f"Identifier {identifier_id} doesn't belong to this user")

    current_identifiers = db.get_identifiers_legal_entity(legal_entity_id)

    current_ids = {row[0] for row in current_identifiers}

    if not current_ids:
        return error_invalid("Legal Entity has no identifiers (invalid state)")

    valid_identifiers_to_remove = [
        i for i in identifier_ids if i in current_ids
    ]

    if not valid_identifiers_to_remove:
        return error_invalid("None of the provided identifiers are associated with this Legal Entity")

    if len(current_ids) - len(valid_identifiers_to_remove) < 1:
        return error_invalid("A Legal Entity must have at least one identifier")

    #delete
    deleted_count = db.delete_legal_entity_identifier(
        legal_entity_id,
        valid_identifiers_to_remove
    )

    return update_response(
        "Legal Entity Identifier associations removed successfully",
        deleted_count
    )

## -policy
@rpr.route('/policy/create', methods=['POST'])
def create_policy():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "policy"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    policies = data.get("policy", [])

    if not isinstance(policies, list):
        return error_invalid("Field 'policy' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #verification
    for policy in policies:
        if not isinstance(policy, dict):
            return error_invalid("Each policy must be an object.")

        missing = validate_required_fields(policy, ["policyURI", "type", "intention"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(policy, {"policyURI": str, "type": str, "intention": str})
        if error:
            return error

        type = policy.get("type")
        intention = policy.get("intention")

        if intention != "intended_use" and intention != "wrp":
            return error_invalid("Invalid intention. 'wrp' or 'intended_use'.")

        if intention == "wrp":
            if type not in cfgserv.relying_party["Type of Policy"]:
                return error_invalid(f"Invalid 'wrp' Type of Policy. Must be one of: {', '.join(cfgserv.relying_party['Type of Policy'])}")

        if intention == "intended_use":
            if type not in cfgserv.intended_use["Type of Privacy Policy"]:
                return error_invalid(f"Invalid 'intended_use' type_policy. Must be one of: {', '.join(cfgserv.intended_use['Type of Privacy Policy'])}")

    #insert data base
    try:
        with db.transaction() as cursor:
            for policy in policies:
                policyURI = policy.get("policyURI")
                type = policy.get("type")

                policy_id = db.insert_policy(policyURI, type, user_id, cursor=cursor)
                result.append(policy_id)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Policy created successfully", "Policy ids", result)

@rpr.route('/policy/list', methods=['POST'])
def list_policy():

    data = request.get_json(silent=True)
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_policy(user_id)

    return list_response("Policies retrieved successfully.", result, "policy")

## -provider
@rpr.route('/provider/create', methods=['POST'])
def create_provider():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "provider"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    providers = data.get("provider", [])

    if not isinstance(providers, list):
        return error_invalid("'provider' must be a list.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    result = []

    #validation
    for provider in providers:
        if not isinstance(provider, dict):
            return error_invalid("Each provider must be an object.")
        
        missing = validate_required_fields(provider, ["legalEntityId", "policy_id", "providerType"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(provider, {"providerType": str})
        if error:
            return error

        if not is_list_of(provider["policy_id"], is_id):
            return error_invalid("Field 'policy_id' must be an array of positive integers.")

        if not is_list_of(provider.get("x5c") or [], is_non_blank_str):
            return error_invalid("Field 'x5c' must be an array of non-empty strings.")

        provider["x5c"] = [value.strip() for value in provider.get("x5c") or []]

        policy_ids = provider["policy_id"]
        for policy_id in policy_ids:
            row = db.check_policy(policy_id)

            if not row or row[0] is None:
                return error_invalid(f"Policy {policy_id} not found")
            if user_id[0] != row[0]:
                return error_invalid(f"The Policy ID {policy_id} does not belong to this user")
            
            if row[1] not in cfgserv.relying_party["Type of Policy"]:
                return error_invalid(f"The policy has an incorrect type; it must be a policy with a type for 'Wallet Relying Party'(intention: wrp). Must be one of: {', '.join(cfgserv.relying_party['Type of Policy'])}")

        legalEntityId = provider.get("legalEntityId")
        
        if not is_id(legalEntityId):
            return error_invalid("Field 'legalEntityId' must be a positive integer.")

        if user_id != db.check_legal_entity(legalEntityId):
            return error_invalid(
                f"The Legal Entity ID {legalEntityId} does not belong to this user"
            )
            
    #insert data base
    try:
        with db.transaction() as cursor:
            for provider in providers:
                legalEntityId = provider.get("legalEntityId")
                providerType = provider.get("providerType")
                x5c = provider.get("x5c") or []
                policy_ids = provider["policy_id"]

                provider_id = db.insert_provider(legalEntityId, providerType, user_id, cursor=cursor)
                result.append(provider_id)

                for policy_id in policy_ids:
                    db.insert_provider_policy(provider_id, policy_id, cursor=cursor)

                for cert in x5c:
                    db.insert_provider_x5c(provider_id, cert, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Provider created successfully", "Provider ids", result)


@rpr.route('/provider/list', methods=['POST'])
def list_provider():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_provider(user_id)

    return list_response("Legal Entity retrieved successfully.", result, "provider")

@rpr.route('/provider/update_policy', methods=['POST'])
def update_provider_policy():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "provider_id", "policy_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    provider_id = data.get("provider_id")
    policy_ids = data.get("policy_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_provider(provider_id):
        return error_invalid(f"Provider id {provider_id} doesn't belong to this user")
    
    for policy_id in policy_ids:
        row = db.check_policy(policy_id)
        
        if user_id[0] != row[0]:
            return error_invalid(f"The Policy ID {policy_id} does not belong to this user")
        if row[1] not in cfgserv.relying_party["Type of Policy"]:
            return error_invalid(f"The policy has an incorrect type; it must be a policy with a type for 'Wallet Relying Party'(intention: wrp). Must be one of: {', '.join(cfgserv.relying_party['Type of Policy'])}")

    #insert data base
    for policy_id in policy_ids:
        db.insert_provider_policy(provider_id, policy_id)

    return update_response("Provider Policy associations updated successfully", len(policy_ids))

@rpr.route('/provider/remove_policy', methods=['POST'])
def remove_provider_policy():

    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "provider_id", "policy_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    provider_id = data.get("provider_id")
    policy_ids = data.get("policy_ids", [])

    if not isinstance(policy_ids, list) or not policy_ids:
        return error_invalid("policy_ids must be a non-empty list")

    policy_ids = list(set(policy_ids))
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    if user_id != db.check_provider(provider_id):
        return error_invalid(f"Provider id {provider_id} doesn't belong to this user")
    
    for policy_id in policy_ids:
        row = db.check_policy(policy_id)
        if not row[0] or user_id[0] != row[0]:
            return error_invalid(f"Policy {policy_id} doesn't belong to this user")

    current_policies = db.get_provider_policy(provider_id)

    current_policy_ids = {row[0] for row in current_policies}

    if not current_policy_ids:
        return error_invalid("Provider has no policies (invalid state)")

    valid_policies_to_remove = [
        p for p in policy_ids if p in current_policy_ids
    ]

    if not valid_policies_to_remove:
        return error_invalid("None of the provided policies are associated with this provider")

    if len(current_policy_ids) - len(valid_policies_to_remove) < 1:
        return error_invalid("A Provider must have at least one policy")

    deleted_count = db.delete_provider_policy(
        provider_id,
        valid_policies_to_remove
    )

    return update_response(
        "Provider Policy associations removed successfully",
        deleted_count
    )

## -credential
def error_server(message="Internal server error. Please try again later.", code=500):
    return {
        "status": "error",
        "code": code,
        "message": message
    }, code

def db_write_error(e, server_message="Database error. No data was saved."):
    if isinstance(e, db.DuplicateError):
        return error_invalid("A record with these values already exists. No data was saved.", code=409)
    if isinstance(e, db.InvalidDataError):
        return error_invalid("Invalid data for one or more fields. No data was saved.")
    return error_server(server_message)

@rpr.route('/credential/create', methods=['POST'])
def create_credential():
 
    data = request.get_json(silent=True)
    if not data:
        return error_response("Invalid or missing JSON body")
 
    missing = validate_required_fields(data, ["hash_pid", "credentials"])
    if missing:
        return error_response("Missing required fields.", missing)
 
    hash_pid = data.get("hash_pid")
    credentials = data.get("credentials", [])
 
    if not isinstance(credentials, list):
        return error_response("Field 'credentials' must be an array.")
 
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
 
    #verification
    for credential in credentials:
        if not isinstance(credential, dict):
            return error_response("Each credential must be an object.")
 
        missing = validate_required_fields(credential, ["format", "meta", "claims"])
        if missing:
            return error_response("Missing required fields.", missing)
 
        if credential["format"] not in cfgserv.formats["SUPPORTED_FORMATS"]:
            return error_invalid(
                f"Invalid credential format. Must be one of: "
                f"{', '.join(cfgserv.formats['SUPPORTED_FORMATS'])}"
            )
 
        if not isinstance(credential["meta"], dict):
            return error_response("Field 'meta' must be an object.")
 
        if not isinstance(credential["claims"], list):
            return error_response("Field 'claims' must be an array.")
 
        for claim in credential["claims"]:
            if not isinstance(claim, dict):
                return error_response("Each claim must be an object.")
 
            missing = validate_required_fields(claim, ["path"])
            if missing:
                return error_response("Missing required fields.", missing)
 
            if not isinstance(claim["path"], list):
                return error_response("Field 'path' must be an array.")
 
            if len(claim["path"]) == 0:
                return error_response("Field 'path' cannot be empty.")
            
    to_insert = [
        {
            "format": credential["format"],
            "meta": serialize_json(credential["meta"]),
            "paths": [serialize_json(claim["path"]) for claim in credential["claims"]],
        }
        for credential in credentials
    ]
 
    try:
        result = db.insert_credentials_with_claims(to_insert, user_id)
    except db.DuplicateCredentialError:
        return error_invalid(
            "A credential with this format already exists for this user.",
            code=409
        )
    except db.DatabaseError as e:
        return db_write_error(e, "Error creating credentials. No data was saved.")
 
    return create_response("Credential created successfully", "Credential ids", result)

@rpr.route('/credential/list', methods=['POST'])
def list_credential():
    data = request.get_json(silent=True)
 
    if not data:
        return error_response("Invalid or missing JSON body")
 
    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
 
    hash_pid = data.get("hash_pid")
 
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
 
    try:
        result = db.get_credentials(user_id)
    except db.DatabaseError:
        return error_server("Error retrieving credentials.")
 
    return list_response("Credentials retrieved successfully.", result, "credential")

## -intended use
@rpr.route('/intended_use/create', methods=['POST'])
def create_intended_use():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_uses"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    intended_uses = data.get("intended_uses", [])

    if not isinstance(intended_uses, list):
        return error_invalid("Field 'intended_uses' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #validation
    for intended_use in intended_uses:

        if not isinstance(intended_use, dict):
            return error_invalid("Each intended use must be an object.")

        missing = validate_required_fields(
            intended_use,
            [
                "intendedUseIdentifier",
                "createdAt",
                "revokedAt",
                "purpose",
                "privacyPolicy_id",
                "credential_ids"
            ]
        )

        if missing:
            return error_response(
                "Missing required fields.",
                missing
            )

        error = check_field_types(
            intended_use,
            {
                "intendedUseIdentifier": str,
                "createdAt": str,
                "revokedAt": str,
                "purpose": list
            }
        )

        if error:
            return error

        for field in ("privacyPolicy_id", "credential_ids"):
            if not is_list_of(intended_use[field], is_id):
                return error_invalid(f"Field '{field}' must be an array of positive integers.")

        created_at = intended_use.get("createdAt")
        revoked_at = intended_use.get("revokedAt")

        try:
            created_at_date = datetime.strptime(
                created_at,
                "%Y-%m-%d"
            ).date()

            revoked_at_date = datetime.strptime(
                revoked_at,
                "%Y-%m-%d"
            ).date()

        except (TypeError, ValueError):
            return error_invalid(
                "createdAt and revokedAt must be valid dates in YYYY-MM-DD format."
            )

        if revoked_at_date <= created_at_date:
            return error_invalid(
                "revokedAt cannot be earlier than createdAt."
            )

        purposes = intended_use.get("purpose", [])

        for purpose in purposes:
            if not isinstance(purpose, dict):
                return error_invalid("Each purpose must be an object.")

            missing = validate_required_fields(
                purpose,
                ["lang", "content"]
            )

            if missing:
                return error_response(
                    "Missing required fields.",
                    missing
                )

            error = check_field_types(purpose, {"lang": str, "content": str})
            if error:
                return error

            lang = purpose.get("lang")

            if lang not in cfgserv.eu_languages:
                return error_invalid(
                    f"Invalid purpose_lang. Must be one of: "
                    f"{', '.join(cfgserv.eu_languages)}"
                )

        privacyPolicy_ids = intended_use.get(
            "privacyPolicy_id",
            []
        )

        for privacyPolicy_id in privacyPolicy_ids:
            row = db.check_policy(privacyPolicy_id)

            if not row or row[0] is None:
                return error_invalid(f"Policy {privacyPolicy_id} not found")

            if user_id[0] != row[0]:
                return error_invalid(
                    f"The Policy ID {privacyPolicy_id} "
                    f"does not belong to this user"
                )

            if row[1] not in cfgserv.intended_use[
                "Type of Privacy Policy"
            ]:
                return error_invalid(
                    "The policy has an incorrect type; it must be "
                    "a policy with a type for 'Wallet Relying Party' "
                    "(intention: wrp). Must be one of: "
                    f"{', '.join(cfgserv.relying_party['Type of Policy'])}"
                )

        credential_ids = intended_use.get(
            "credential_ids",
            []
        )

        for credential_id in credential_ids:
            if user_id != db.check_credentials(credential_id):
                return error_invalid(
                    f"The Credential ID {credential_id} "
                    f"does not belong to this user."
                )
            
    try:
        with db.transaction() as cursor:
            for intended_use in intended_uses:
                intendedUseIdentifier = intended_use.get("intendedUseIdentifier")
                purposes = intended_use.get("purpose", [])
                privacyPolicy_ids = intended_use.get("privacyPolicy_id", [])
                credential_ids = intended_use.get("credential_ids", [])

                createdAt = intended_use.get("createdAt")
                revokedAt = intended_use.get("revokedAt")

                intended_use_id = db.insert_intended_use(intendedUseIdentifier, createdAt, revokedAt, user_id, cursor=cursor)
                result.append(intended_use_id)

                for purpose in purposes:
                    lang = purpose.get("lang")
                    content = purpose.get("content")

                    mls_id = db.insert_multilanguage_string(lang, content, user_id, cursor=cursor)
                    db.insert_intended_use_purpose(intended_use_id, mls_id, cursor=cursor)

                for privacyPolicy_id in privacyPolicy_ids:
                    db.insert_intended_use_policy(intended_use_id, privacyPolicy_id, cursor=cursor)

                for credential_id in credential_ids:
                    db.insert_intended_use_credential(intended_use_id, credential_id, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Intended Use created successfully", "Intended Use ids", result)

@rpr.route('/intended_use/list', methods=['POST'])
def list_intended_use():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_intended_use(user_id)

    return list_response("Intended Use retrieved successfully.", result, "intended_use")

@rpr.route('/intended_use/update_credential', methods=['POST'])
def update_intended_use_credential():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_use_id", "credential_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    intended_use_id = data.get("intended_use_id")
    credential_ids = data.get("credential_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_intendedUse(intended_use_id):
        return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")
    
    for credential_id in credential_ids:
        if user_id != db.check_credentials(credential_id):
            return error_invalid(f"Credential id {credential_id} doesn't belong to this user")
        
    #insert data base
    for credential_id in credential_ids:
        db.insert_intended_use_credential(intended_use_id, credential_id)

    return update_response("Intended Use Credential associations updated successfully", len(credential_ids))

@rpr.route('/intended_use/update_policy', methods=['POST'])
def update_intended_use_policy():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_use_id", "policy_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    intended_use_id = data.get("intended_use_id")
    policy_ids = data.get("policy_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_intendedUse(intended_use_id):
        return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")
    
    for policy_id in policy_ids:
        row = db.check_policy(policy_id)
        
        if user_id[0] != row[0]:
            return error_invalid(f"The Policy ID {policy_id} does not belong to this user")
        if row[1] not in cfgserv.intended_use["Type of Privacy Policy"]:
            return error_invalid(f"The policy has an incorrect type; it must be a policy with a type for 'Intended Use'(intention: intended_use). Must be one of: {', '.join(cfgserv.relying_party['Type of Policy'])}")

    #insert data base
    for policy_id in policy_ids:
        db.insert_intended_use_policy(intended_use_id, policy_id)

    return update_response("Intended Use Policy associations updated successfully", len(policy_ids))

@rpr.route('/intended_use/remove_credential', methods=['POST'])
def remove_intended_use_credential():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_use_id", "credential_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    intended_use_id = data.get("intended_use_id")
    credential_ids = data.get("credential_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_intendedUse(intended_use_id):
        return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")
    
    for credential_id in credential_ids:
        if user_id != db.check_credentials(credential_id):
            return error_invalid(f"Credential id {credential_id} doesn't belong to this user")

    current_credentials = db.get_intended_use_credential(intended_use_id)

    current_credential_ids = {row[0] for row in current_credentials}

    if not current_credential_ids:
        return error_invalid("Provider has no credentials (invalid state)")

    valid_credentials_to_remove = [
        p for p in credential_ids if p in current_credential_ids
    ]

    if not valid_credentials_to_remove:
        return error_invalid("None of the provided credentials are associated with this Intended Use")

    if len(current_credential_ids) - len(valid_credentials_to_remove) < 1:
        return error_invalid("A Intended Use must have at least one Credential")
        
    #insert data base
    deleted_count = db.delete_intended_use_credential(intended_use_id, credential_ids)

    return update_response(
        "Intended Use Credential associations removed successfully",
        deleted_count
    )

@rpr.route('/intended_use/remove_policy', methods=['POST'])
def remove_intended_use_policy():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_use_id", "policy_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    intended_use_id = data.get("intended_use_id")
    policy_ids = data.get("policy_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_intendedUse(intended_use_id):
        return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")
    
    for policy_id in policy_ids:
        row = db.check_policy(policy_id)
        
        if user_id[0] != row[0]:
            return error_invalid(f"The Policy ID {policy_id} does not belong to this user")
        
    current_policies = db.get_intended_use_policy(intended_use_id)

    current_policy_ids = {row[0] for row in current_policies}

    if not current_policy_ids:
        return error_invalid("Intended Use has no policies (invalid state)")

    valid_policies_to_remove = [
        p for p in policy_ids if p in current_policy_ids
    ]

    if not valid_policies_to_remove:
        return error_invalid("None of the provided policies are associated with this Intended Use")

    if len(current_policy_ids) - len(valid_policies_to_remove) < 1:
        return error_invalid("A Intended Use must have at least one policy")
        
    #insert data base  
    deleted_count = db.delete_intended_use_policy(intended_use_id, policy_ids)

    return update_response(
        "Intended Use Policy associations removed successfully",
        deleted_count
    )

## -provided attestation
@rpr.route('/provided_attestation/create', methods=['POST'])
def create_provided_attestation():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "providesAttestations"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    providesAttestations = data.get("providesAttestations", [])

    if not isinstance(providesAttestations, list):
        return error_invalid("Field 'providesAttestations' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #validation
    for providesAttestation in providesAttestations:
        if not isinstance(providesAttestation, dict):
            return error_invalid("Each providesAttestation must be an object.")

        missing = validate_required_fields(providesAttestation, ["format", "meta"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(providesAttestation, {"format": str})
        if error:
            return error

        if not isinstance(providesAttestation["meta"], dict):
            return error_response(
                "Field 'meta' must be an object."
            )
        
        if providesAttestation["format"] not in cfgserv.formats["SUPPORTED_FORMATS"]:
            return error_invalid(
                f"Invalid Provides Attestation format. Must be one of: "
                f"{', '.join(cfgserv.formats['SUPPORTED_FORMATS'])}"
            )
    
    #insert data base
    try:
        with db.transaction() as cursor:
            for providesAttestation in providesAttestations:
                format = providesAttestation.get("format")
                meta = serialize_json(providesAttestation["meta"])

                provided_attestation_id = db.insert_provided_attestation(format, meta, user_id, cursor=cursor)
                result.append(provided_attestation_id)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Provided Attestation created successfully.", "Provided Attestation ids", result)

@rpr.route('/provided_attestation/list', methods=['POST'])
def list_provided_attestation():
    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_provided_attestation(user_id)

    return list_response("Provided attestation retrieved successfully.", result, "provided_attestation")

## -supervisoryAuthority
@rpr.route('/supervisory_authority/create', methods=['POST'])
def create_supervisory_authority():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "supervisoryAuthority"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    supervisoryAuthority = data.get("supervisoryAuthority", [])

    if not isinstance(supervisoryAuthority, list):
        return error_invalid("Field 'supervisoryAuthority' must be an array.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = []

    #validation
    for aux in supervisoryAuthority:
        if not isinstance(aux, dict):
            return error_invalid("Each supervisoryAuthority must be an object.")

        missing = validate_required_fields(aux, ["name", "country"])
        if missing:
            return error_response("Missing required fields.", missing)

        error = check_field_types(aux, {"name": str, "country": str})
        if error:
            return error

        for field in ("email", "formURI", "phone"):
            if not is_list_of(aux.get(field) or [], is_non_blank_str):
                return error_invalid(f"Field '{field}' must be an array of non-empty strings.")

            aux[field] = [value.strip() for value in aux.get(field) or []]

        emails = aux.get("email") or []
        formuris = aux.get("formURI") or []
        phones = aux.get("phone") or []
        country = aux.get("country")

        if country not in cfgserv.eu_countries:
            return error_invalid(f"Invalid country. Must be one of: {', '.join(cfgserv.eu_countries)}")

        if not emails and not formuris and not phones:
            return error_response("At least one of the following fields is required.", "email, formURI or phone")
        
    #insert data base
    try:
        with db.transaction() as cursor:
            for aux in supervisoryAuthority:

                name = aux.get("name")
                country = aux.get("country")
                emails = aux.get("email") or []
                formuris = aux.get("formURI") or []
                phones = aux.get("phone") or []

                supervisory_authority_id = db.insert_supervisory_authority(name, country, user_id, cursor=cursor)
                result.append(supervisory_authority_id)

                for email in emails:
                    db.insert_supervisory_authority_email(supervisory_authority_id, email, cursor=cursor)

                for formUri in formuris:
                    db.insert_supervisory_authority_formuri(supervisory_authority_id, formUri, cursor=cursor)

                for phone in phones:
                    db.insert_supervisory_authority_phone(supervisory_authority_id, phone, cursor=cursor)
    except db.DatabaseError as e:
        return db_write_error(e)

    return create_response("Supervisory Authority created successfully", "Supervisory Authority ids", result)

@rpr.route('/supervisory_authority/list', methods=['POST'])
def list_supervisory_authority():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")
    
    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_supervisory_authority(user_id)

    return list_response("Supervisory Authority retrieved successfully.", result, "supervisory_authority")

## -wrp
def validate_wrp_services(wrp_services, user_id, claimed_intended_uses):
    """Validates a list of WalletRelyingPartyService objects (types, ownership, uniqueness).

    Returns (error, normalized_services). error is a Flask response tuple or None.
    claimed_intended_uses is a set shared by the whole request, so the same Intended Use
    cannot be given to two services in one request.
    """
    if not isinstance(wrp_services, list) or not wrp_services or not all(isinstance(svc, dict) for svc in wrp_services):
        return error_response("Field 'WalletRelyingPartyService' must be a non-empty array of objects."), None

    entitlement_values = cfgserv.relying_party["Entitlement"]
    normalized = []

    for svc in wrp_services:
        missing = validate_required_fields(svc, ["serviceTradeName", "serviceIdentifier", "supportURIs", "srvDescription", "email", "phone"])
        if missing:
            return error_response("Missing required fields.", missing), None

        for field in ("serviceTradeName", "serviceIdentifier", "email", "phone"):
            if not is_non_blank_str(svc[field]) or len(svc[field].strip()) > 255:
                return error_invalid(f"{field} must be a non-empty string with at most 255 characters."), None

        if "isIntermediary" in svc and not isinstance(svc["isIntermediary"], bool):
            return error_invalid("isIntermediary must be a boolean."), None

        for field in ("intendedUse_ids", "providesAttestations_ids", "usesIntermediary", "servedWRPServices"):
            ids = svc.get(field) or []
            if not is_list_of(ids, is_id):
                return error_invalid(f"{field} must be an array of positive integers."), None

            # Repeated ids in the request are a 400; 409 is reserved for conflicts with existing rows
            repeated = sorted({value for value in ids if ids.count(value) > 1})
            if repeated:
                return error_invalid(f"{field} contains repeated ids: {', '.join(map(str, repeated))}."), None

        for field in ("entitlements", "subEntitlements"):
            if not is_list_of(svc.get(field) or [], is_str):
                return error_invalid(f"{field} must be an array of strings."), None

        if not is_list_of(svc["supportURIs"], is_non_blank_str):
            return error_invalid("supportURIs must be an array of non-empty strings."), None

        if not is_list_of(svc["srvDescription"], lambda value: isinstance(value, dict)):
            return error_invalid("srvDescription must be an array of objects."), None

        srv_descriptions = []
        for srvDescription in svc["srvDescription"]:
            missing = validate_required_fields(srvDescription, ["lang", "content"])
            if missing:
                return error_response("Missing required fields.", missing), None

            if not isinstance(srvDescription["lang"], str) or not isinstance(srvDescription["content"], str):
                return error_invalid("srvDescription lang and content must be strings."), None

            if srvDescription["lang"] not in cfgserv.eu_languages:
                return error_invalid(f"Invalid srvDescription_lang. Must be one of: {', '.join(cfgserv.eu_languages)}"), None

            srv_descriptions.append({"lang": srvDescription["lang"], "content": srvDescription["content"].strip()})

        intendedUse_ids = svc.get("intendedUse_ids") or []
        entitlements = svc.get("entitlements") or []
        subEntitlements = svc.get("subEntitlements") or []
        providesAttestations_ids = svc.get("providesAttestations_ids") or []
        usesIntermediarys = svc.get("usesIntermediary") or []
        servedWRPServices = svc.get("servedWRPServices") or []

        for entitlement in entitlements:
            if entitlement not in entitlement_values:
                return error_invalid(f"Invalid entitlement. Must be one of: {', '.join(entitlement_values)}"), None

        for sub_entitlement in subEntitlements:
            if sub_entitlement not in entitlement_values:
                return error_invalid(f"Invalid sub entitlement. Must be one of: {', '.join(entitlement_values)}"), None

        for servedWRPService in servedWRPServices:
            if user_id != db.check_wrp_service(servedWRPService):
                return error_invalid(f"The served WRP Service ID {servedWRPService} does not belong to this user"), None

        for usesIntermediary in usesIntermediarys:
            if user_id != db.check_wrp_service(usesIntermediary):
                return error_invalid(f"The usesIntermediary ID {usesIntermediary} does not belong to this user"), None

            if db.check_wrp_intermediary(usesIntermediary) != 1:
                return error_invalid(f"The usesIntermediary ID {usesIntermediary} is not a Intermediary Wallet Relying Party Service"), None

        for providesAttestations_id in providesAttestations_ids:
            if user_id != db.check_provided_attestation(providesAttestations_id):
                return error_invalid(f"The providesAttestations ID {providesAttestations_id} does not belong to this user"), None

        for intendedUse_id in intendedUse_ids:
            if user_id != db.check_intendedUse(intendedUse_id):
                return error_invalid(f"The intendedUse ID {intendedUse_id} does not belong to this user"), None

            if intendedUse_id in claimed_intended_uses:
                return error_invalid(f"intendedUse_ids contains repeated ids across services in this request: {intendedUse_id}."), None

            if db.check_wrp_intendedUse(intendedUse_id) != []:
                return error_invalid(f"Intended Use id {intendedUse_id} already belongs to other wallet relying party service"), None

            claimed_intended_uses.add(intendedUse_id)

        normalized.append({
            "serviceTradeName": svc["serviceTradeName"].strip(),
            "serviceIdentifier": svc["serviceIdentifier"].strip(),
            "email": svc["email"].strip(),
            "phone": svc["phone"].strip(),
            # A service that uses intermediaries cannot itself be an intermediary
            "isIntermediary": False if usesIntermediarys else svc.get("isIntermediary", False),
            "entitlements": entitlements,
            "subEntitlements": subEntitlements,
            "usesIntermediary": usesIntermediarys,
            "supportURIs": [value.strip() for value in svc["supportURIs"]],
            "srvDescription": srv_descriptions,
            "providesAttestations_ids": providesAttestations_ids,
            "intendedUse_ids": intendedUse_ids,
            "servedWRPServices": servedWRPServices,
        })

    return None, normalized

@rpr.route('/wallet_rp/create', methods=['POST'])
def create_wrp():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")
    
    missing = validate_required_fields(data, ["hash_pid", "WalletRelyingParty"])
    
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    wrps = data.get("WalletRelyingParty", [])

    if not isinstance(wrps, list) or not all(isinstance(wrp, dict) for wrp in wrps):
        return error_response("Field 'WalletRelyingParty' must be a non-empty array of objects.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    #validation
    to_insert = []
    claimed_intended_uses = set()

    for wrp in wrps:
        missing = validate_required_fields(wrp, ["provider_id", "isPSB", "supervisoryAuthority", "registryURI", "WalletRelyingPartyService"])
        if missing:
            return error_response("Missing required fields.", missing)

        if not isinstance(wrp["isPSB"], bool):
            return error_invalid("isPSB must be a boolean.")

        for field in ("provider_id", "supervisoryAuthority"):
            if not is_id(wrp[field]):
                return error_invalid(f"{field} must be a positive integer.")

        if not isinstance(wrp["registryURI"], str):
            return error_invalid("registryURI must be a string.")

        tradeName = wrp.get("tradeName")
        if tradeName is not None and (not isinstance(tradeName, str) or len(tradeName) > 255):
            return error_invalid("tradeName must be a string with at most 255 characters.")

        supervisoryAuthority = wrp.get("supervisoryAuthority")
        provider_id = wrp.get("provider_id")

        if user_id != db.check_supervisory_authority(supervisoryAuthority):
            return error_invalid(f"The supervisoryAuthority ID {supervisoryAuthority} does not belong to this user")

        if user_id != db.check_provider(provider_id):
                return error_invalid(f"The Provider ID {provider_id} does not belong to this user")

        error, wrp_services = validate_wrp_services(wrp["WalletRelyingPartyService"], user_id, claimed_intended_uses)
        if error:
            return error

        to_insert.append({
            "provider_id": provider_id,
            "tradeName": tradeName,
            "isPSB": wrp["isPSB"],
            "registryURI": wrp["registryURI"],
            "supervisoryAuthority": supervisoryAuthority,
            "WalletRelyingPartyService": wrp_services,
        })

    #insert data base
    try:
        created = db.insert_wrps_with_services_atomic(to_insert, user_id)
    except db.DatabaseError as e:
        return db_write_error(e, "Error creating Wallet Relying Party. No data was saved.")

    result = []
    for wrp_id, wrp_service_ids in created:
        result.append("Wallet Relying Party: " + str(wrp_id))
        for wrp_service_id in wrp_service_ids:
            result.append("Wallet Relying Party service: " + str(wrp_service_id))

    return create_response("Wallet Relying Party and Wallet Relying Party service created successfully", "wrp ids", result)

@rpr.route('/wallet_rp/list', methods=['POST'])
def list_wrp():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_wrp(user_id)

    return list_response("Wallet Relying Party retrieved successfully.", result, "wrp")

@rpr.route('/wallet_rp/update_wrp_service', methods=['POST'])
def update_wrp_service():
    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "WalletRelyingParty_id", "WalletRelyingPartyService_ids"])
    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    WalletRelyingParty_id = data.get("WalletRelyingParty_id")
    WalletRelyingPartyService_ids = data.get("WalletRelyingPartyService_ids") or []

    if not is_id(WalletRelyingParty_id):
        return error_invalid("WalletRelyingParty_id must be a positive integer.")

    if not is_list_of(WalletRelyingPartyService_ids, is_id):
        return error_invalid("WalletRelyingPartyService_ids must be an array of positive integers.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    #verification
    if user_id != db.check_wrp(WalletRelyingParty_id):
        return error_invalid(f"Wallet Relying Party id {WalletRelyingParty_id} doesn't belong to this user")

    for WalletRelyingPartyService_id in WalletRelyingPartyService_ids:
        if user_id != db.check_wrp_service(WalletRelyingPartyService_id):
            return error_invalid(f"Wallet Relying Party Service id {WalletRelyingPartyService_id} doesn't belong to this user")

        if db.check_wrp_wrpService(WalletRelyingPartyService_id) != []:
            return error_invalid(f"Wallet Relying Party Service id {WalletRelyingPartyService_id} already belongs to other wallet relying party.")

    #insert data base
    try:
        updated = db.update_wrp_wrpServices_atomic(WalletRelyingParty_id, WalletRelyingPartyService_ids)
    except db.DatabaseError as e:
        return db_write_error(e, "Error associating Wallet Relying Party Services. No data was saved.")

    return update_response("Wallet Relying Party Wallet Relying Party Service associations updated successfully", updated)

@rpr.route('/wallet_rp/remove_wrp_service', methods=['POST'])
def remove_wrp_service():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(
        data,
        [
            "hash_pid",
            "WalletRelyingParty_id",
            "WalletRelyingPartyService_ids"
        ]
    )

    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    wallet_relying_party_id = data.get("WalletRelyingParty_id")
    wallet_relying_party_service_ids = data.get(
        "WalletRelyingPartyService_ids",
        []
    )

    user_id = db.check_user(hash_pid)

    if user_id is None:
        return error_invalid("Invalid hash_pid")

    if user_id != db.check_wrp(wallet_relying_party_id):
        return error_invalid(
            f"Wallet Relying Party id {wallet_relying_party_id} "
            f"doesn't belong to this user"
        )

    for service_id in wallet_relying_party_service_ids:

        if user_id != db.check_wrp_service(service_id):
            return error_invalid(
                f"Wallet Relying Party Service id {service_id} "
                f"doesn't belong to this user"
            )

    current_wrp_services = db.get_wrp_wrpService(
        wallet_relying_party_id
    )

    current_wrp_service_ids = {
        row[0] for row in current_wrp_services
    }

    if not current_wrp_service_ids:
        return error_invalid(
            "Wallet Relying Party has no Wallet Relying Party Service "
            "(invalid state)"
        )

    valid_wrp_service_to_remove = [
        service_id
        for service_id in wallet_relying_party_service_ids
        if service_id in current_wrp_service_ids
    ]

    if not valid_wrp_service_to_remove:
        return error_invalid(
            "None of the provided Wallet Relying Party Services "
            "are associated with this Wallet Relying Party"
        )

    remaining_services = (
        len(current_wrp_service_ids)
        - len(valid_wrp_service_to_remove)
    )

    if remaining_services < 1:
        return error_invalid(
            "A Wallet Relying Party must have at least "
            "one Wallet Relying Party Service"
        )

    deleted_count = db.delete_wrp_wrp_service(
        wallet_relying_party_id,
        valid_wrp_service_to_remove
    )

    return update_response(
        "Wallet Relying Party / Wallet Relying Party Service "
        "associations removed successfully",
        deleted_count
    )

## wrp_service
@rpr.route('/wallet_rp_service/create', methods=['POST'])
def create_wrp_service():

    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "WalletRelyingParty", "WalletRelyingPartyService"])

    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    wrp = data.get("WalletRelyingParty")

    if not is_id(wrp):
        return error_invalid("WalletRelyingParty must be a positive integer.")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    #validation
    if user_id != db.check_wrp(wrp):
        return error_invalid(f"The Wallet RelyingParty ID {wrp} does not belong to this user")

    error, wrp_services = validate_wrp_services(data.get("WalletRelyingPartyService"), user_id, set())
    if error:
        return error

    #insert data base
    try:
        result = db.insert_wrp_services_atomic(wrp, wrp_services, user_id)
    except db.DatabaseError as e:
        return db_write_error(e, "Error creating Wallet Relying Party Service. No data was saved.")

    return create_response("Wallet Relying Party Service created successfully", "Wallet Relying Party Service new IDs", result)

@rpr.route('/wallet_rp_service/list', methods=['POST'])
def list_wrp_service():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    result = db.get_wrp_service(user_id)

    return list_response("Wallet Relying Party Service retrieved successfully.", result, "wrp_service")

@rpr.route('/wallet_rp_service/update_intended_use', methods=['POST'])
def update_wrp_intended_use():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "intended_use_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    intended_use_ids = data.get("intended_use_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for intended_use_id in intended_use_ids:
        if user_id != db.check_intendedUse(intended_use_id):
            return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")

        if db.check_wrp_intendedUse(intended_use_id) != []:
            return error_invalid(f"Intended Use id {intended_use_id} already belongs to other wallet relying party service")

    #insert data base
    for intended_use_id in intended_use_ids:
        db.insert_wrp_intended_use(wrp_service_id, intended_use_id)

    return update_response("Wallet Relying Party Intended Use associations updated successfully", len(intended_use_ids))

@rpr.route('/wallet_rp_service/update_provided_attestation', methods=['POST'])
def update_wrp_provided_attestion():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "provided_attestation_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    provided_attestation_ids = data.get("provided_attestation_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for provided_attestation_id in provided_attestation_ids:
        if user_id != db.check_provided_attestation(provided_attestation_id):
            return error_invalid(f"Provided Attestation id {provided_attestation_id} doesn't belong to this user")
        
    #insert data base
    for provided_attestation_id in provided_attestation_ids:
        db.insert_wrp_provided_attestation(wrp_service_id, provided_attestation_id)

    return update_response("Wallet Relying Party Provided Attestation associations updated successfully", len(provided_attestation_ids))

@rpr.route('/wallet_rp_service/update_uses_intermediary', methods=['POST'])
def update_wrp_uses_intermediary():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "uses_intermediary_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    uses_intermediary_ids = data.get("uses_intermediary_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for uses_intermediary_id in uses_intermediary_ids:
        if user_id != db.check_wrp_service(uses_intermediary_id):
            return error_invalid(f"Wallet Relying Party Service id {uses_intermediary_id} doesn't belong to this user")
        
        if db.check_wrp_intermediary(uses_intermediary_id) != 1:
            return error_invalid(f"The usesIntermediary ID {uses_intermediary_id} is not a Intermediary Wallet Relying Party Service")

        if db.check_wrp_intermediary_with_wpr(wrp_service_id, uses_intermediary_id) != []:
            return error_invalid(f"The usesIntermediary ID {uses_intermediary_id} is already an intermediary of this Wallet Relying Party Service")
        
    #insert data base
    for uses_intermediary_id in uses_intermediary_ids:
        db.insert_wrp_intermediary(wrp_service_id, uses_intermediary_id)

    return update_response("Wallet Relying Party Service uses Intermediary associations updated successfully", len(uses_intermediary_ids))

@rpr.route('/wallet_rp_service/remove_intended_use', methods=['POST'])
def remove_wrp_intended_use():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "intended_use_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    intended_use_ids = data.get("intended_use_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for intended_use_id in intended_use_ids:
        if user_id != db.check_intendedUse(intended_use_id):
            return error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user")
        
    current_intended_use = db.get_wrp_intendedUse(wrp_service_id)

    current_intended_use_ids = {row[0] for row in current_intended_use}

    if not current_intended_use_ids:
        return error_invalid("Wallet Relying Party Service has no intended use (invalid state)")

    valid_intended_use_to_remove = [
        p for p in intended_use_ids if p in current_intended_use_ids
    ]

    if not valid_intended_use_to_remove:
        return error_invalid("None of the provided Intended Uses are associated with this Wallet Relying Party Service")

    # if len(current_intended_use_ids) - len(valid_intended_use_to_remove) < 1:
    #     return error_invalid("A Wallet Relying Party Service must have at least one Intended Use")
        
    #insert data base  
    deleted_count = db.delete_wrp_intended_use(wrp_service_id, intended_use_ids)

    return update_response(
        "Wallet Relying Party Service Intended Use associations removed successfully",
        deleted_count
    )

@rpr.route('/wallet_rp_service/remove_provided_attestation', methods=['POST'])
def remove_wrp_provided_attestion():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "provided_attestation_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    provided_attestation_ids = data.get("provided_attestation_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for provided_attestation_id in provided_attestation_ids:
        if user_id != db.check_provided_attestation(provided_attestation_id):
            return error_invalid(f"Provided Attestation id {provided_attestation_id} doesn't belong to this user")
        
    #insert data base
    deleted_count = db.delete_wrp_provided_attestion(wrp_service_id, provided_attestation_ids)

    return update_response(
        "Wallet Relying Party Service Provided Attestation associations removed successfully",
        deleted_count
    )

@rpr.route('/wallet_rp_service/remove_uses_intermediary', methods=['POST'])
def remove_wrp_uses_intermediary():
    data = request.get_json(silent=True)
   
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "uses_intermediary_ids"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    uses_intermediary_ids = data.get("uses_intermediary_ids", [])
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    #verification
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    for uses_intermediary_id in uses_intermediary_ids:
        if user_id != db.check_wrp_service(uses_intermediary_id):
            return error_invalid(f"Wallet Relying Party Service id {uses_intermediary_id} doesn't belong to this user")
        
    #insert data base
    deleted_count = db.delete_wrp_intermediary(wrp_service_id, uses_intermediary_ids)

    return update_response(
        "Wallet Relying Party Service uses Intermediary associations removed successfully",
        deleted_count
    )
@rpr.route('/list_claim', methods=['POST'])
def list_claim():
    data = request.get_json(silent=True)
 
    if not data:
        return error_response("Invalid or missing JSON body")
 
    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
 
    hash_pid = data.get("hash_pid")
 
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
 
    try:
        result = db.get_claim(user_id)
    except db.DatabaseError:
        return error_server("Error retrieving claims.")
 
    return list_response("Claims retrieved successfully.", result, "claim")

@rpr.route('/list_full_info', methods=['POST'])
def list_full_info():
    data = request.get_json(silent=True)
    
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    
    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")

    legal_entities = db.get_legal_entity(user_id)
    providers = db.get_provider(user_id)
    wrps = db.get_wrp(user_id)
    wrp_services = db.get_wrp_service(user_id)
    intended_uses = db.get_intended_use(user_id)

    result = []

    provider_by_le = {}
    for p in providers:
        provider_by_le.setdefault(p["legal_entity_id"], []).append(p)

    wrp_by_provider = {}
    for w in wrps:
        wrp_by_provider.setdefault(w["provider_id"], []).append(w)

    iu_by_id = {iu["intended_use_id"]: iu for iu in intended_uses}

    # TS5/TS6: service data (Intended Uses included) belongs to the Wallet Relying Party Services
    service_details = {
        s["wrp_service_id"]: {
            "entitlements": s["entitlements"],
            "subEntitlements": s["subEntitlements"],
            "srvDescription": s["srvDescription"],
            "supportURI": s["supportURI"],
            "usesIntermediary": s["usesIntermediary"],
            "servedWRPServices": s["servedWRPServices"],
            "providedAttestation": s["provides_attestations"],
            "intendedUses": s["intendedUses"],
        }
        for s in wrp_services
    }

    iu_refs_by_wrp = {}
    for s in wrp_services:
        refs = iu_refs_by_wrp.setdefault(s["wrp_id"], [])
        for iu_ref in s.get("intendedUses", []):
            if iu_ref not in refs:
                refs.append(iu_ref)

    for le in legal_entities:

        le_id = le["legal_entity_id"]

        le_obj = le.copy()
        le_obj["providers"] = []

        for p in provider_by_le.get(le_id, []):

            p_id = p["provider_id"]

            p_obj = p.copy()
            p_obj["wrp"] = []

            for w in wrp_by_provider.get(p_id, []):

                w_obj = w.copy()
                w_obj["wallet_relying_party_service"] = [
                    {**service, **service_details.get(service["wrp_service_id"], {})}
                    for service in w.get("wallet_relying_party_service", [])
                ]

                full_iu = []

                for iu_ref in iu_refs_by_wrp.get(w["wrp_id"], []):
                    iu_id = iu_ref["id"]

                    if iu_id in iu_by_id:
                        full_iu.append(iu_by_id[iu_id])

                w_obj["intended_use"] = full_iu

                p_obj["wrp"].append(w_obj)

            le_obj["providers"].append(p_obj)

        result.append(le_obj)

    return list_response("Info retrieved successfully.", result, "data")

@rpr.route('/wrp', methods=['GET'])
def search_wrp_public():

    identifier = request.args.get("identifier")
    legalname = request.args.get("legalname")
    tradename = request.args.get("tradename")
    policy = request.args.get("policy")
    entitlement = request.args.get("entitlement")
    providesattestation = request.args.get("providesattestation")
    intendeduseidentifier = request.args.get("intendeduseidentifier")
    isintermediary = request.args.get("isintermediary")
    usesintermediary = request.args.get("usesintermediary")

    if isintermediary is not None:
        if isintermediary.lower() == "true":
            isintermediary = 1
        elif isintermediary.lower() == "false":
            isintermediary = 0
        else:
            isintermediary = None 

    result = db.search_wrp_public(
        identifier=identifier,
        legalname=legalname,
        tradename=tradename,
        policy=policy,
        entitlement=entitlement,
        providesattestation=providesattestation,
        intendeduseidentifier=intendeduseidentifier,
        isintermediary=isintermediary,
        usesintermediary=usesintermediary
    )
    
    final_result= json.dumps(result)

    key = import_private_ec_key_from_file(cfgserv.wrprc_privateKey)
    ec_key = ECKey(priv_key=key)

    jws = JWS(final_result, alg="ES256")

    signed_jws = jws.sign_json([ec_key])

    return signed_jws


@rpr.route('/wrp/<identifier>', methods=['GET'])
def get_wrp_by_identifier(identifier):

    wrp = db.get_wrp_by_identifier(identifier)

    if not wrp:
        return error_invalid("Wallet Relying Party not found")

    key = import_private_ec_key_from_file(cfgserv.wrprc_privateKey)
    ec_key = ECKey(priv_key=key)

    jws = JWS(json.dumps(wrp), alg="ES256")

    signed_jws = jws.sign_json([ec_key])

    return signed_jws

@rpr.route('/wrp/check-intended-use', methods=['GET'])
def check_intended_use():

    identifier = request.args.get("identifier")
    claim_path = request.args.get("claim_path")
    credential_format = request.args.get("credential_format")
    credential_meta = request.args.get("credential_meta")
    intended_use_identifier = request.args.get("intended_use_identifier")

    if not identifier:
        return error_response("Missing required fields.", "identifier")

    exists = db.check_intended_use(
        identifier,
        claim_path,
        credential_format,
        credential_meta,
        intended_use_identifier
    )
    
    key = import_private_ec_key_from_file(cfgserv.wrprc_privateKey)
    ec_key = ECKey(priv_key=key)

    jws = JWS(json.dumps(exists), alg="ES256")

    signed_jws = jws.sign_json([ec_key])

    return signed_jws

# @rpr.route("/static/swagger.json")
# def swagger_static():
#     return send_from_directory("static", "swagger.json")

@rpr.route("/guide")
def guide():
    return render_template("guide.html")

@rpr.route("/wallet_rp/certificate", methods=["POST"])
def wrp_access_certificate():
    
    data = request.get_json(silent=True)
        
    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "wrp_service_id", "password"])
    if missing:
        return error_response("Missing required fields.", missing)
    
    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    password = data.get("password")

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")
    
    wrp_service = db.get_wrp_service_id(wrp_service_id)

    if not wrp_service:
        return error_invalid(
            f"Wallet Relying Party Service {wrp_service_id} "
            f"doesn't have a Wallet Relying Party associated."
        )
    
    wrp = db.get_wrp_id(wrp_service[0]["wrp_id"])

    modulus=crypto.key_size
    exponent=crypto.exponent
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend() )

    #dados da RP
    TypeIdentifier={
        "http://data.europa.eu/eudi/id/EORI-No":"EOR",
        "http://data.europa.eu/eudi/id/LEI":"LEI" ,
        "http://data.europa.eu/eudi/id/EUID":"NTR" ,
        "http://data.europa.eu/eudi/id/VATIN":"VAT"  ,
        "http://data.europa.eu/eudi/id/TIN":"TIN",
        "http://data.europa.eu/eudi/id/Excise":"EXC"
    }
    #commonName
    tradeName = wrp_service[0]["wrp_service_trade_name"]

    #uniformResourceIdentifier
    supportURI = wrp_service[0]["supportURI"][0]

    legal_entity = db.get_legal_entity_id(wrp[0]["provider_id"])
    
    #dados da legalEntity
    #caso for natural person é serialNumber no caso de uma legal person organizationIdentifier
    identifier = legal_entity[0]["identifier"]
    country = legal_entity[0]["country"]

    email = None
    if email:
        email = legal_entity[0]["email"][0]
    phone = None
    if phone:
        phone = legal_entity[0]["phone"][0]

    if legal_entity[0]["LegalPerson"] is None:
        #se user for natural person
        givenName=legal_entity[0]["NaturalPerson"]["givenName"]
        #surname
        surname=legal_entity[0]["NaturalPerson"]["familyName"]

        first = legal_entity[0]["identifier"][0]
        country_code = "XG" if TypeIdentifier[first['type']] == "LEI" else country

        serial_number = (
            f"{TypeIdentifier[first['type']]}"
            f"{country_code}-"
            f"{first['identifier']}"
        )

        certificateRequest= generateCertificateRequest(priv_key=priv_key, commonName=tradeName, countryName=country, uniformResourceIdentifier=supportURI, 
                                                       givenName=givenName, surname=surname, serialNumber=serial_number, email=email)
        
    else:
        #se user for legal person
        #dados da legal person
        #organizationName
        legalName = legal_entity[0]["LegalPerson"]["legalName"][0]

        first = legal_entity[0]["identifier"][0]
        country_code = "XG" if TypeIdentifier[first['type']] == "LEI" else country

        organizationIdentifier = (
            f"{TypeIdentifier[first['type']]}"
            f"{country_code}-"
            f"{first['identifier']}"
        )
        
        certificateRequest = generateCertificateRequest(priv_key=priv_key, commonName=tradeName, countryName=country, uniformResourceIdentifier=supportURI, 
                                                       organizationName=legalName, organizationIdentifier=organizationIdentifier, email=None)

    #como as TSLs, ex: lang en, description=test  
    #servicesDescription=RP[0]["srvDescription"]#como as TSLs, ex: lang en, description=test  
    #entitlement=RP[0]["entitlement"]
    # verificar legal entity se é pertence ao sector público, se sim True, se não False
    #isPSB= False
#### ------
    # password=request.form.get("Password")


    certificateRequestString = "-----BEGIN CERTIFICATE REQUEST-----\n"+ base64.b64encode(certificateRequest).decode("utf-8") + "\n"+ "-----END CERTIFICATE REQUEST-----"
    certificateAuthorityName = getCertificateAuthorityName(country)
    certificateRequestBody = getJsonBody(certificateRequestString, certificateAuthorityName, country)

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

    certificate = response.get("certificate")

    if not certificate:
        extra = {"response": response}
        logger.error("Error EJBCA response.", extra=extra)
        return error_invalid("Error EJBCA response.")

    certificate_bytes = base64.b64decode(certificate)

    certificate = x509.load_der_x509_certificate(certificate_bytes, default_backend())

    serial_number=response["serial_number"]

    p12=pkcs12.serialize_key_and_certificates(
        name=tradeName.encode("utf-8"),key=priv_key,cert=certificate, cas=list().append(trustCA),
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    tag = uuid.uuid4()

    file_name = tradeName + "_" + str(tag)

    p12_temp.update({file_name:{"response": p12, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})

    cert = certificate.subject.rfc4514_string().split(",")
    dic = {parte.split("=")[0]: parte for parte in cert}
    order = [dic.get("C"),
            #dic.get("O"),
            dic.get("CN")]
    aux = [v for k, v in dic.items() if k not in ["C", "O", "CN"]]

    cert_subject_rfc4514_string = ",".join(order + aux)

    certificate_presentation={
        "certificate_issuer":certificate.issuer.rfc4514_string(),
        "certificate_distinguished_name":cert_subject_rfc4514_string,
        "validity_from":certificate.not_valid_before_utc,
        "validity_to":certificate.not_valid_after_utc,
    }

    file_base64 = base64.b64encode(p12).decode()
    serial_number = response["serial_number"]

    db.insert_access_certificate(
        pkcs12_certificate=file_base64,
        serial_number=serial_number,
        subject=cert_subject_rfc4514_string,
        state="ACTIVE",
        created_at=datetime.now(),
        expires_at=certificate.not_valid_after_utc,
        wrp_id=wrp_service[0]["wrp_id"],
        user_id=user_id
    )

    return jsonify({
        "status": "success",
        "code": 200,
        "data": {
            "filename": "document_with_signature.json",
            "file_base64": file_base64
        }
    })

## -registration certificate (WRPRC)

# (connect, read) timeout, in seconds, of every outbound request of the certificate routes
EXTERNAL_HTTP_TIMEOUT = (5, 30)

# Characters of an external service's response body kept in the log
EXTERNAL_BODY_EXCERPT = 300

STATUS_LIST_SERVICE = "Status list service"
SIGNING_SERVICE = "Signing service"

PRIVACY_POLICY_TYPES = [
    policy_type
    for policy_type in cfgserv.intended_use["Type of Privacy Policy"]
    if policy_type.rsplit("/", 1)[-1] in ("privacy-policy", "privacy-statement")
]

TYPE_IDENTIFIER_PREFIX = {
    "http://data.europa.eu/eudi/id/EORI-No": "EOR",
    "http://data.europa.eu/eudi/id/LEI": "LEI",
    "http://data.europa.eu/eudi/id/EUID": "NTR",
    "http://data.europa.eu/eudi/id/VATIN": "VAT",
    "http://data.europa.eu/eudi/id/TIN": "TIN",
    "http://data.europa.eu/eudi/id/Excise": "EXC",
}

SIGNER_HASH_ALGORITHM_OID = "2.16.840.1.101.3.4.2.1"


class CertificateIssueError(Exception):
    """Stops certificate issuance with a ready-made API error response."""

    def __init__(self, response):
        super().__init__(response[0]["message"])
        self.response = response


def run_certificate_route(handler):
    # No exception may reach Flask: expected failures carry their response,
    # anything else becomes the API's generic 500 with the traceback logged.
    try:
        return handler()
    except CertificateIssueError as e:
        return e.response
    except Exception:
        logger.exception(f"Unhandled error on {request.method} {request.path}")
        return error_server()


def require_first(items, message, code=400):
    if not items:
        if code >= 500:
            logger.error(message)
        raise CertificateIssueError(error_invalid(message, code=code))
    return items[0]


def invalid_external_response(service, detail):
    logger.error(f"{service} returned an invalid response: {detail}")
    return CertificateIssueError(error_invalid(f"{service} returned an invalid response", code=502))


def post_external(service, url, **kwargs):
    """POST to an external service and return its JSON object body.

    Raises CertificateIssueError (502) when the service is unreachable, answers
    with an HTTP error or does not answer with a JSON object. Request headers
    are never logged: they may carry API keys.
    """
    try:
        response = requests.post(url, timeout=EXTERNAL_HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as e:
        logger.error(f"{service} request to {url} failed: {e!r}")
        raise CertificateIssueError(error_invalid(f"{service} unavailable", code=502))

    try:
        body = response.json()
    except ValueError:
        body = None

    excerpt = response.text[:EXTERNAL_BODY_EXCERPT]

    if not response.ok:
        logger.error(f"{service} at {url} returned HTTP {response.status_code}: {excerpt!r}")
        message = body.get("message") if isinstance(body, dict) else None
        if isinstance(message, str) and message.strip():
            message = f"{service} error: {message.strip()}"
        else:
            message = f"{service} error"
        raise CertificateIssueError(error_invalid(message, code=502))

    if not isinstance(body, dict):
        raise invalid_external_response(
            service, f"HTTP {response.status_code} without a JSON object body: {excerpt!r}"
        )

    return body


def request_status_list(expires_at):
    body = post_external(
        STATUS_LIST_SERVICE,
        cfgserv.url_statuslist,
        headers={
            "accept": "application/json",
            "X-API-Key": cfgserv.statuslist_apikey,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "country": "FC",
            "doctype": "wrprc",
            "expiry_date": expires_at.strftime("%Y-%m-%d"),
        },
    )

    status_list = body.get("status_list")
    if not isinstance(status_list, dict) or "idx" not in status_list or not status_list.get("uri"):
        raise invalid_external_response(
            STATUS_LIST_SERVICE, f"no status_list with idx and uri (keys: {sorted(body)})"
        )

    return {"idx": status_list["idx"], "uri": status_list["uri"]}


def signer_calculate_hash(request_body):
    """Return the (CBOR, JSON) SHA-256 digests to sign and the signature date."""
    body = post_external(
        SIGNING_SERVICE,
        cfgserv.sca_signer_url + "/signatures/calculate_hash",
        headers={"Content-Type": "application/json"},
        data=json.dumps(request_body).encode(),
    )

    digests = body.get("hashes")
    signature_date = body.get("signature_date")
    if (
        not isinstance(digests, list)
        or len(digests) < 2
        or not all(isinstance(digest, str) for digest in digests[:2])
        or not signature_date
    ):
        raise invalid_external_response(
            SIGNING_SERVICE, f"calculate_hash without two hashes and a signature_date (keys: {sorted(body)})"
        )

    try:
        to_sign = [base64.b64decode(urllib.parse.unquote(digest)) for digest in digests[:2]]
    except ValueError as e:
        raise invalid_external_response(SIGNING_SERVICE, f"calculate_hash hashes are not base64: {e}")

    if any(len(digest) != hashes.SHA256.digest_size for digest in to_sign):
        raise invalid_external_response(SIGNING_SERVICE, "calculate_hash hashes are not SHA-256 digests")

    return to_sign[0], to_sign[1], signature_date


def signer_obtain_signed_doc(request_body):
    """Return the signed certificate as (base64url JWT, base64 COSE)."""
    body = post_external(
        SIGNING_SERVICE,
        cfgserv.sca_signer_url + "/signatures/obtain_signed_doc",
        headers={"Content-Type": "application/json"},
        data=json.dumps(request_body).encode(),
    )

    documents = body.get("documentWithSignature")
    if (
        not isinstance(documents, list)
        or len(documents) < 2
        or not all(isinstance(document, str) for document in documents[:2])
    ):
        raise invalid_external_response(
            SIGNING_SERVICE, f"obtain_signed_doc without two signed documents (keys: {sorted(body)})"
        )

    try:
        jades = json.loads(base64.b64decode(documents[1]).decode("utf-8"))
        signature = jades["signatures"][0]
        jwt = signature["protected"] + "." + jades["payload"] + "." + signature["signature"]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise invalid_external_response(SIGNING_SERVICE, f"obtain_signed_doc JAdES document is malformed: {e!r}")

    return base64.urlsafe_b64encode(jwt.encode()).decode(), documents[0]


def load_certificate_base64(path):
    """Base64 of the PEM encoding of the certificate at path, stored as PEM or DER."""
    with open(path, "rb") as f:
        raw = f.read()

    if raw.lstrip().startswith(b"-----BEGIN"):
        cert = x509.load_pem_x509_certificate(raw, default_backend())
    else:
        cert = x509.load_der_x509_certificate(raw, default_backend())

    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("utf-8")


def wrprc_certificate_chain():
    if not cfgserv.wrprc_intermediate:
        return []
    return [load_certificate_base64(cfgserv.wrprc_intermediate)]


def sign_wrprc_digest(digest):
    with open(cfgserv.wrprc_privateKey, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return base64.b64encode(signature).decode()


def encode_wrprc(json_payload):
    """The claims as the two documents the signer signs: (base64 CBOR, base64 JSON)."""
    base64_cbor = base64.b64encode(cbor2.dumps(json_payload)).decode("utf-8")
    base64_json = base64.b64encode(json.dumps(json_payload).encode()).decode("utf-8")
    return base64_cbor, base64_json


def signer_documents(base64_cbor, base64_json):
    return [
        {
            "document": base64_cbor,
            "signature_format": "CB",
            "conformance_level": "Ades-B-B",
            "signed_envelope_property": "ENVELOPING",
            "container": "No"
        },
        {
            "document": base64_json,
            "signature_format": "J",
            "conformance_level": "Ades-B-B",
            "signed_envelope_property": "ENVELOPING",
            "container": "No"
        }
    ]


def select_privacy_policy(intended_use_id, policies):
    if not policies:
        raise CertificateIssueError(error_invalid(
            f"Intended Use {intended_use_id} has no privacy policy; "
            f"a privacy policy is required to issue a registration certificate."
        ))

    for policy in policies:
        if policy.get("type") in PRIVACY_POLICY_TYPES:
            return policy["policyURI"]

    logger.warning(
        f"Intended Use {intended_use_id} has no policy of type {' or '.join(PRIVACY_POLICY_TYPES)}; "
        f"using policy {policies[0].get('policy_id')} of type {policies[0].get('type')} as privacy_policy."
    )
    return policies[0]["policyURI"]


def entity_sub(legal_entity, label):
    identifier = require_first(
        legal_entity.get("identifier"),
        f"{label} has no identifier; an identifier is required to issue a registration certificate."
    )

    prefix = TYPE_IDENTIFIER_PREFIX.get(identifier.get("type"))
    if prefix is None:
        raise CertificateIssueError(error_invalid(
            f"{label} identifier type '{identifier.get('type')}' is not supported in registration certificates."
        ))

    country_code = "XG" if prefix == "LEI" else legal_entity.get("country")

    return f"{prefix}{country_code}-{identifier['identifier']}"


def load_certificate_subject(data):
    """Validate the request against the database and return the records the certificate is built from."""
    intended_use_id = data.get("intended_use_id")

    user_id = db.check_user(data.get("hash_pid"))
    if user_id is None:
        raise CertificateIssueError(error_invalid("Invalid hash_pid"))

    if user_id != db.check_intendedUse(intended_use_id):
        raise CertificateIssueError(error_invalid(f"Intended Use id {intended_use_id} doesn't belong to this user"))

    intended_use = require_first(
        db.get_intended_use_id(intended_use_id),
        f"Error retrieving Intended Use {intended_use_id}.",
        code=500
    )

    wrp_service = require_first(
        db.get_wrp_service_id(db.get_wrps_intended_use(intended_use_id)),
        f"Intended Use id {intended_use_id} doesn't have a Wallet Relying Party Service associated."
    )

    intermediary_id = data.get("intermediary_id")
    if intermediary_id:
        if user_id != db.check_wrp_service(intermediary_id):
            raise CertificateIssueError(error_invalid(
                f"Wallet Relying Party Service id {intermediary_id} doesn't belong to this user"
            ))

        wrp_intermediary = db.get_wrp_intermediary(intermediary_id)
        if not wrp_intermediary or wrp_service["wrp_service_id"] != wrp_intermediary[0]:
            raise CertificateIssueError(error_invalid(
                f"The usesIntermediary ID {intermediary_id} does not belong to this Wallet Relying Party"
            ))

    wrp = require_first(
        db.get_wrp_id(wrp_service["wrp_id"]),
        f"Error retrieving the Wallet Relying Party of service {wrp_service['wrp_service_id']}.",
        code=500
    )

    legal_entity = require_first(
        db.get_legal_entity_id(wrp["provider_id"]),
        f"Error retrieving the Legal Entity of Wallet Relying Party {wrp_service['wrp_id']}.",
        code=500
    )

    return {
        "user_id": user_id,
        "intended_use_id": intended_use_id,
        "intended_use": intended_use,
        "wrp_service": wrp_service,
        "wrp": wrp,
        "legal_entity": legal_entity,
        "intermediary_id": intermediary_id,
    }


def build_wrprc_payload(subject, iat, public_body):
    """Claims of the WRPRC, validated before any external call.

    'status' is left as None, in its place: it is filled in after the status
    list call, so that an invalid request never takes a status list index.
    """
    intended_use = subject["intended_use"]
    wrp_service = subject["wrp_service"]
    legal_entity = subject["legal_entity"]

    support_uri = require_first(
        wrp_service.get("supportURI"),
        f"Wallet Relying Party Service {wrp_service['wrp_service_id']} has no support URI; "
        f"a support URI is required to issue a registration certificate."
    )

    json_payload = {
        "name": wrp_service["wrp_service_trade_name"],
        "purpose": intended_use["purpose"],
        "country": legal_entity["country"],
        "sub": entity_sub(legal_entity, "Legal Entity"),
        "registry_uri": cfgserv.service_url,
        "privacy_policy": select_privacy_policy(subject["intended_use_id"], intended_use.get("privacyPolicy")),
        "policy_id": [
            "0.4.0.19475.3.1"
        ],
        "iat": iat,
        "credentials": intended_use.get("credentials", []),
        "entitlements": wrp_service["entitlements"],
        "public_body": public_body,
        "srv_description": wrp_service["srvDescription"],
        "support_uri": support_uri,
        "status": None
    }

    if legal_entity.get("infoURI"):
        json_payload["info_uri"] = legal_entity["infoURI"][0]

    if wrp_service.get("provides_attestations"):
        json_payload["provides_attestations"] = wrp_service["provides_attestations"]

    sa = subject["wrp"].get("SupervisoryAuthority")
    if sa:
        supervisory_authority = {}

        if sa.get("email"):
            supervisory_authority["email"] = sa["email"][0]

        if sa.get("phone"):
            supervisory_authority["phone"] = sa["phone"][0]

        if sa.get("formURI"):
            supervisory_authority["uri"] = sa["formURI"][0]

        if supervisory_authority:
            json_payload["supervisory_authority"] = supervisory_authority

    certificate_policy = cfgserv.service_url + "certificate_policy"
    legal_person = legal_entity.get("LegalPerson")

    if legal_person is None:
        natural_person = legal_entity.get("NaturalPerson")
        if not natural_person:
            raise CertificateIssueError(error_invalid(
                "Legal Entity has neither legal person nor natural person data; "
                "one of them is required to issue a registration certificate."
            ))

        json_payload.update({
            "sub_gn": natural_person.get("givenName"),
            "sub_fn": natural_person.get("familyName"),
            "certificate_policy": certificate_policy
        })
    else:
        json_payload.update({
            "sub_ln": require_first(
                legal_person.get("legalName"),
                "Legal Entity has no legal name; a legal name is required to issue a registration certificate."
            ),
            "certificate_policy": certificate_policy
        })

    intermediary_id = subject["intermediary_id"]
    if intermediary_id:
        rp_intermediary = require_first(
            db.get_wrp_service_id(intermediary_id),
            f"Error retrieving intermediary Wallet Relying Party Service {intermediary_id}.",
            code=500
        )
        wrp_intermediary = require_first(
            db.get_wrp_id(rp_intermediary["wrp_id"]),
            f"Error retrieving the Wallet Relying Party of intermediary {intermediary_id}.",
            code=500
        )
        legal_entity_intermediary = require_first(
            db.get_legal_entity_id(wrp_intermediary["provider_id"]),
            f"Error retrieving the Legal Entity of intermediary {intermediary_id}.",
            code=500
        )

        json_payload["intermediary"] = {
            "sub": entity_sub(legal_entity_intermediary, "Intermediary Legal Entity"),
            "sname": rp_intermediary["wrp_service_trade_name"]
        }

    return json_payload


def certificate_success_response(file_base64, cose_base64):
    return jsonify({
        "status": "success",
        "code": 200,
        "data": {
            "filename": "document_with_signature.json",
            "file_base64": file_base64,
            "cose_base64": cose_base64
        }
    })


@rpr.route("/intended_use/certificate", methods=["POST"])
def intended_use_registration_certificate():
    return run_certificate_route(issue_intended_use_certificate)


def issue_intended_use_certificate():
    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(data, ["hash_pid", "intended_use_id"])
    if missing:
        return error_response("Missing required fields.", missing)

    subject = load_certificate_subject(data)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=6*30)

    json_payload = build_wrprc_payload(subject, iat=int(now.timestamp()), public_body=subject["wrp"]["isPSB"])
    json_payload["status"] = {"status_list": request_status_list(expires_at)}

    base64_cbor, base64_json = encode_wrprc(json_payload)

    request_body = {
        "documents": signer_documents(base64_cbor, base64_json),
        "hashAlgorithmOID": SIGNER_HASH_ALGORITHM_OID,
        "returnValidationInfo": False,
        "endEntityCertificate": load_certificate_base64(cfgserv.wrprc_certificate),
        "certificateChain": wrprc_certificate_chain()
    }

    digest_cbor, digest_jwt, signature_date = signer_calculate_hash(request_body)

    request_body.update({
        "signatures": [sign_wrprc_digest(digest_cbor), sign_wrprc_digest(digest_jwt)],
        "date": signature_date
    })

    file_base64, cose_base64 = signer_obtain_signed_doc(request_body)

    certificate_id = db.insert_registration_certificate(
        jwt_certificate=file_base64,
        cbor_certificate=cose_base64,
        state="ACTIVE",
        created_at=now,
        expires_at=expires_at,
        intended_use_id=subject["intended_use_id"],
        user_id=subject["user_id"],
    )

    if certificate_id is None:
        return error_server("Error saving the registration certificate.")

    return certificate_success_response(file_base64, cose_base64)


@rpr.route("/wallet_rp/certificate_error", methods=["POST"])
def wrp_access_certificate_error():
    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(
        data,
        ["hash_pid", "wrp_service_id", "password", "error_type"]
    )

    if missing:
        return error_response("Missing required fields.", missing)

    hash_pid = data.get("hash_pid")
    wrp_service_id = data.get("wrp_service_id")
    password = data.get("password")
    error_type = data.get("error_type")

    supported_errors = ["invalid_signature", "expired"]

    if error_type not in supported_errors:
        return error_invalid(
            "Invalid error_type.",
            {
                "allowed_values": supported_errors
            }
        )

    user_id = db.check_user(hash_pid)
    if user_id is None:
        return error_invalid("Invalid hash_pid")
    
    if user_id != db.check_wrp_service(wrp_service_id):
        return error_invalid(f"Wallet Relying Party Service id {wrp_service_id} doesn't belong to this user")

    wrp_service = db.get_wrp_service_id(wrp_service_id)

    if not wrp_service:
        return error_invalid(
            f"Wallet Relying Party Service {wrp_service_id} "
            f"doesn't have a Wallet Relying Party associated."
        )

    wrp = db.get_wrp_id(wrp_service[0]["wrp_id"])

    modulus=crypto.key_size
    exponent=crypto.exponent
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend() )

    #dados da RP
    TypeIdentifier={
        "http://data.europa.eu/eudi/id/EORI-No":"EOR",
        "http://data.europa.eu/eudi/id/LEI":"LEI" ,
        "http://data.europa.eu/eudi/id/EUID":"NTR" ,
        "http://data.europa.eu/eudi/id/VATIN":"VAT"  ,
        "http://data.europa.eu/eudi/id/TIN":"TIN",
        "http://data.europa.eu/eudi/id/Excise":"EXC"
    }
    #commonName
    tradeName = wrp_service[0]["wrp_service_trade_name"]

    #uniformResourceIdentifier
    supportURI = wrp_service[0]["supportURI"][0]

    legal_entity = db.get_legal_entity_id(wrp[0]["provider_id"])
    
    #dados da legalEntity
    #caso for natural person é serialNumber no caso de uma legal person organizationIdentifier
    identifier = legal_entity[0]["identifier"]
    country = legal_entity[0]["country"]

    email = None
    if email:
        email = legal_entity[0]["email"][0]
    phone = None
    if phone:
        phone = legal_entity[0]["phone"][0]

    if legal_entity[0]["LegalPerson"] is None:
        #se user for natural person
        givenName=legal_entity[0]["NaturalPerson"]["givenName"]
        #surname
        surname=legal_entity[0]["NaturalPerson"]["familyName"]

        first = legal_entity[0]["identifier"][0]
        country_code = "XG" if TypeIdentifier[first['type']] == "LEI" else country

        serial_number = (
            f"{TypeIdentifier[first['type']]}"
            f"{country_code}-"
            f"{first['identifier']}"
        )

        certificateRequest= generateCertificateRequest(priv_key=priv_key, commonName=tradeName, countryName=country, uniformResourceIdentifier=supportURI, 
                                                       givenName=givenName, surname=surname, serialNumber=serial_number, email=email)
        
    else:
        #se user for legal person
        #dados da legal person
        #organizationName
        legalName = legal_entity[0]["LegalPerson"]["legalName"][0]

        first = legal_entity[0]["identifier"][0]
        country_code = "XG" if TypeIdentifier[first['type']] == "LEI" else country

        organizationIdentifier = (
            f"{TypeIdentifier[first['type']]}"
            f"{country_code}-"
            f"{first['identifier']}"
        )
        
        certificateRequest = generateCertificateRequest(priv_key=priv_key, commonName=tradeName, countryName=country, uniformResourceIdentifier=supportURI, 
                                                       organizationName=legalName, organizationIdentifier=organizationIdentifier, email=None)

    #como as TSLs, ex: lang en, description=test  
    #servicesDescription=RP[0]["srvDescription"]#como as TSLs, ex: lang en, description=test  
    #entitlement=RP[0]["entitlement"]
    # verificar legal entity se é pertence ao sector público, se sim True, se não False
    isPSB= False
#### ------
    # password=request.form.get("Password")


    certificateRequestString = "-----BEGIN CERTIFICATE REQUEST-----\n"+ base64.b64encode(certificateRequest).decode("utf-8") + "\n"+ "-----END CERTIFICATE REQUEST-----"
    certificateAuthorityName = getCertificateAuthorityName(country)
    certificateRequestBody = getJsonBody(certificateRequestString, certificateAuthorityName, country)

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

    certificate = response.get("certificate")

    if not certificate:
        extra = {"response": response}
        logger.error("Error EJBCA response.", extra=extra)
        return error_invalid("Error EJBCA response.")

    certificate_bytes = base64.b64decode(certificate)

    certificate = x509.load_der_x509_certificate(certificate_bytes, default_backend())

    serial_number=response["serial_number"]

    if error_type == "expired":
        now = datetime.now(timezone.utc)

        certificate = (
            x509.CertificateBuilder()
            .subject_name(certificate.subject)
            .issuer_name(certificate.issuer)
            .public_key(certificate.public_key())
            .serial_number(certificate.serial_number)
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=1))
            .sign(
                private_key=priv_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        )

    elif error_type == "invalid_signature":
        invalid_signature_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )

        certificate_builder = (
            x509.CertificateBuilder()
            .subject_name(certificate.subject)
            .issuer_name(certificate.issuer)
            .public_key(certificate.public_key())
            .serial_number(certificate.serial_number)
            .not_valid_before(certificate.not_valid_before_utc)
            .not_valid_after(certificate.not_valid_after_utc)
        )

        for extension in certificate.extensions:
            certificate_builder = certificate_builder.add_extension(
                extension.value,
                critical=extension.critical
            )

        certificate = certificate_builder.sign(
            private_key=invalid_signature_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

    p12=pkcs12.serialize_key_and_certificates(
        name=tradeName.encode("utf-8"),key=priv_key,cert=certificate, cas=[trustCA],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    tag = uuid.uuid4()

    file_name = tradeName + "_" + str(tag)

    p12_temp.update({file_name:{"response": p12, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})

    cert = certificate.subject.rfc4514_string().split(",")
    dic = {parte.split("=")[0]: parte for parte in cert}
    order = [dic.get("C"),
            #dic.get("O"),
            dic.get("CN")]
    aux = [v for k, v in dic.items() if k not in ["C", "O", "CN"]]

    cert_subject_rfc4514_string = ",".join(order + aux)

    certificate_presentation={
        "certificate_issuer":certificate.issuer.rfc4514_string(),
        "certificate_distinguished_name":cert_subject_rfc4514_string,
        "validity_from":certificate.not_valid_before_utc,
        "validity_to":certificate.not_valid_after_utc,
    }

    file_base64 = base64.b64encode(p12).decode()
    serial_number = response["serial_number"]

    return jsonify({
        "status": "success",
        "code": 200,
        "data": {
            "filename": "document_with_signature.json",
            "file_base64": file_base64
        }
    })

@rpr.route("/intended_use/certificate_error", methods=["POST"])
def intended_use_registration_certificate_error():
    return run_certificate_route(issue_intended_use_certificate_error)


def issue_intended_use_certificate_error():
    data = request.get_json(silent=True)

    if not data:
        return error_response("Invalid or missing JSON body")

    missing = validate_required_fields(
        data,
        ["hash_pid", "intended_use_id", "error_type"]
    )

    if missing:
        return error_response("Missing required fields.", missing)

    error_type = data.get("error_type")

    supported_errors = ["invalid_signature"]

    if error_type not in supported_errors:
        return error_invalid(
            "Invalid error_type.",
            {
                "allowed_values": supported_errors
            }
        )

    subject = load_certificate_subject(data)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=6*30)

    json_payload = build_wrprc_payload(subject, iat=int(now.timestamp()), public_body=False)
    json_payload["status"] = {"status_list": request_status_list(expires_at)}

    base64_cbor, base64_json = encode_wrprc(json_payload)
    base64_cert = load_certificate_base64(cfgserv.wrprc_certificate)

    digest_cbor, digest_jwt, signature_date = signer_calculate_hash({
        "documents": signer_documents(base64_cbor, base64_json),
        "endEntityCertificate": base64_cert,
        "certificateChain": [],
        "hashAlgorithmOID": SIGNER_HASH_ALGORITHM_OID
    })

    signatures = [sign_wrprc_digest(digest_cbor), sign_wrprc_digest(digest_jwt)]

    if error_type == "invalid_signature":
        # The signatures were computed over the original claims: changing a claim
        # now yields a certificate whose signature does not verify.
        json_payload["name"] = "Invalid Signature"
        base64_cbor, base64_json = encode_wrprc(json_payload)

    file_base64, cose_base64 = signer_obtain_signed_doc({
        "documents": signer_documents(base64_cbor, base64_json),
        "hashAlgorithmOID": SIGNER_HASH_ALGORITHM_OID,
        "returnValidationInfo": False,
        "endEntityCertificate": base64_cert,
        "certificateChain": wrprc_certificate_chain(),
        "signatures": signatures,
        "date": signature_date
    })

    return certificate_success_response(file_base64, cose_base64)