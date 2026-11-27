"""POST /intended_use/certificate and /intended_use/certificate_error.

The database, the Status List service and the SCA signer are mocked; the WRPRC
signing key and certificate are generated in a temporary directory.
"""
import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from app import create_app
from app import RPR_routes as routes

STATUS_LIST_URL = "https://status-list.test/take"
SIGNER_URL = "https://signer.test"
API_KEY = "status-list-api-key-must-not-be-logged"

PRIVACY_POLICY = "http://data.europa.eu/eudi/policy/privacy-policy"
TERMS = "http://data.europa.eu/eudi/policy/terms-and-conditions"

ROUTES = ["/intended_use/certificate", "/intended_use/certificate_error"]

JWS_PROTECTED = "eyJhbGciOiJFUzI1NiJ9"
JWS_SIGNATURE = "c2lnbmF0dXJl"
COSE_DOCUMENT = base64.b64encode(b"signed-cose").decode()


def request_body(route):
    body = {"hash_pid": "hash-pid", "intended_use_id": 11}
    if route.endswith("_error"):
        body["error_type"] = "invalid_signature"
    return body


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(params=["pem", "der"])
def wrprc_key(request, tmp_path, monkeypatch):
    """A throwaway WRPRC signing key and self-signed certificate (PEM or DER file)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test WRPRC signer")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    key_path = tmp_path / "wrprc_key.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    encoding = serialization.Encoding.PEM if request.param == "pem" else serialization.Encoding.DER
    cert_path = tmp_path / f"wrprc_cert.{request.param}"
    cert_path.write_bytes(cert.public_bytes(encoding))

    cfg = routes.cfgserv
    monkeypatch.setattr(cfg, "wrprc_privateKey", str(key_path))
    monkeypatch.setattr(cfg, "wrprc_certificate", str(cert_path))
    monkeypatch.setattr(cfg, "wrprc_intermediate", None)
    monkeypatch.setattr(cfg, "url_statuslist", STATUS_LIST_URL)
    monkeypatch.setattr(cfg, "statuslist_apikey", API_KEY)
    monkeypatch.setattr(cfg, "sca_signer_url", SIGNER_URL)
    return key.public_key()


@pytest.fixture
def records():
    """Database records the mocked models return; tests mutate them before the request."""
    return {
        "intended_use": [{
            "intended_use_id": 11,
            "intendedUseIdentifier": "USE-001",
            "purpose": [{"lang": "en", "value": "Log in"}],
            "privacyPolicy": [
                {"policy_id": 1, "policyURI": "https://rp.test/terms", "type": TERMS},
                {"policy_id": 2, "policyURI": "https://rp.test/privacy", "type": PRIVACY_POLICY},
            ],
            "credentials": [{"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:test"]}, "claim": []}],
        }],
        "wrp_service": [{
            "wrp_service_id": 21,
            "wrp_id": 31,
            "wrp_service_trade_name": "Test Service",
            "supportURI": ["https://rp.test/support"],
            "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
            "srvDescription": [{"lang": "en", "content": "A test service"}],
        }],
        "wrp": [{"provider_id": 41, "isPSB": True, "SupervisoryAuthority": None}],
        "legal_entity": [{
            "country": "PT",
            "infoURI": ["https://rp.test"],
            "identifier": [{"identifier": "123456789", "type": "http://data.europa.eu/eudi/id/VATIN"}],
            "LegalPerson": {"legalName": ["Test Lda"]},
            "NaturalPerson": None,
        }],
        "inserted": [],
        "insert_result": 99,
    }


@pytest.fixture
def fake_db(monkeypatch, records):
    db = routes.db
    monkeypatch.setattr(db, "check_user", lambda hash_pid: 7)
    monkeypatch.setattr(db, "check_intendedUse", lambda intended_use_id: 7)
    monkeypatch.setattr(db, "get_intended_use_id", lambda intended_use_id: records["intended_use"])
    monkeypatch.setattr(db, "get_wrps_intended_use", lambda intended_use_id: [(21,)])
    monkeypatch.setattr(db, "get_wrp_service_id", lambda wrp_service_id: records["wrp_service"])
    monkeypatch.setattr(db, "get_wrp_id", lambda wrp_id: records["wrp"])
    monkeypatch.setattr(db, "get_legal_entity_id", lambda provider_id: records["legal_entity"])

    def insert_registration_certificate(**kwargs):
        records["inserted"].append(kwargs)
        return records["insert_result"]

    monkeypatch.setattr(db, "insert_registration_certificate", insert_registration_certificate)
    return records


def make_response(status_code=200, json_body=None, text=None):
    response = requests.Response()
    response.status_code = status_code
    if json_body is not None:
        response._content = json.dumps(json_body).encode()
        response.headers["Content-Type"] = "application/json"
    else:
        response._content = (text or "").encode()
        response.headers["Content-Type"] = "text/html"
    response.url = "https://external.test"
    return response


class FakeServices:
    """Stands in for requests.post: answers as the Status List and the SCA signer."""

    def __init__(self):
        self.calls = []
        self.overrides = {}

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        endpoint = self.endpoint(url)
        override = self.overrides.get(endpoint)
        if isinstance(override, Exception):
            raise override
        if override is not None:
            return override
        return getattr(self, endpoint)(json.loads(kwargs["data"]) if endpoint != "status_list" else kwargs)

    @staticmethod
    def endpoint(url):
        if url == STATUS_LIST_URL:
            return "status_list"
        if url == SIGNER_URL + "/signatures/calculate_hash":
            return "calculate_hash"
        if url == SIGNER_URL + "/signatures/obtain_signed_doc":
            return "obtain_signed_doc"
        raise AssertionError(f"unexpected POST {url}")

    def called(self, endpoint):
        return [kwargs for url, kwargs in self.calls if self.endpoint(url) == endpoint]

    def status_list(self, kwargs):
        return make_response(json_body={"status_list": {"idx": 5, "uri": "https://status.test/list/1"}})

    def calculate_hash(self, body):
        digests = [
            base64.b64encode(hashlib.sha256(base64.b64decode(doc["document"])).digest()).decode()
            for doc in body["documents"]
        ]
        return make_response(json_body={"hashes": digests, "signature_date": 1700000000000})

    def obtain_signed_doc(self, body):
        jades = {
            "payload": body["documents"][1]["document"],
            "signatures": [{"protected": JWS_PROTECTED, "signature": JWS_SIGNATURE}],
        }
        documents = [COSE_DOCUMENT, base64.b64encode(json.dumps(jades).encode()).decode()]
        return make_response(json_body={"documentWithSignature": documents})


@pytest.fixture
def services(monkeypatch, wrprc_key, fake_db):
    fake = FakeServices()
    monkeypatch.setattr(routes.requests, "post", fake)
    return fake


def signed_claims(services):
    """The JSON claims sent to obtain_signed_doc."""
    body = json.loads(services.called("obtain_signed_doc")[0]["data"])
    return json.loads(base64.b64decode(body["documents"][1]["document"]))


def assert_error(response, code, message=None):
    assert response.status_code == code, response.get_data(as_text=True)
    body = response.get_json()
    assert body["status"] == "error"
    assert body["code"] == code
    if message is not None:
        assert body["message"] == message
    return body


# --- happy path ---------------------------------------------------------------

def test_certificate_is_issued_signed_and_stored(client, services, wrprc_key, fake_db):
    response = client.post("/intended_use/certificate", json=request_body("/intended_use/certificate"))

    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json()["data"]

    claims = signed_claims(services)
    expected_jwt = f"{JWS_PROTECTED}.{base64.b64encode(json.dumps(claims).encode()).decode()}.{JWS_SIGNATURE}"
    assert data["file_base64"] == base64.urlsafe_b64encode(expected_jwt.encode()).decode()
    assert data["cose_base64"] == COSE_DOCUMENT

    assert claims["privacy_policy"] == "https://rp.test/privacy"
    assert claims["status"] == {"status_list": {"idx": 5, "uri": "https://status.test/list/1"}}
    assert claims["sub"] == "VATPT-123456789"
    assert claims["sub_ln"] == "Test Lda"
    assert claims["support_uri"] == "https://rp.test/support"
    assert claims["info_uri"] == "https://rp.test"
    assert claims["public_body"] is True

    # The signatures sent to the signer verify against the digests it returned.
    calculate = json.loads(services.called("calculate_hash")[0]["data"])
    obtain = json.loads(services.called("obtain_signed_doc")[0]["data"])
    for document, signature in zip(calculate["documents"], obtain["signatures"]):
        digest = hashlib.sha256(base64.b64decode(document["document"])).digest()
        wrprc_key.verify(base64.b64decode(signature), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    [inserted] = fake_db["inserted"]
    assert inserted["jwt_certificate"] == data["file_base64"]
    assert inserted["cbor_certificate"] == COSE_DOCUMENT
    assert inserted["intended_use_id"] == 11
    assert inserted["user_id"] == 7

    assert [kwargs["timeout"] for _, kwargs in services.calls] == [routes.EXTERNAL_HTTP_TIMEOUT] * 3


def test_certificate_error_signs_then_alters_the_claims(client, services, fake_db):
    response = client.post("/intended_use/certificate_error", json=request_body("/intended_use/certificate_error"))

    assert response.status_code == 200, response.get_data(as_text=True)
    assert signed_claims(services)["name"] == "Invalid Signature"
    calculate = json.loads(services.called("calculate_hash")[0]["data"])
    assert json.loads(base64.b64decode(calculate["documents"][1]["document"]))["name"] == "Test Service"
    assert fake_db["inserted"] == []
    assert [kwargs["timeout"] for _, kwargs in services.calls] == [routes.EXTERNAL_HTTP_TIMEOUT] * 3


# --- Status List ----------------------------------------------------------------

@pytest.mark.parametrize("route", ROUTES)
def test_status_list_html_error_is_502(client, services, route, caplog):
    services.overrides["status_list"] = make_response(502, text="<html><body>Bad Gateway</body></html>")

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Status list service error")
    assert "HTTP 502" in caplog.text and "Bad Gateway" in caplog.text
    assert API_KEY not in caplog.text
    assert services.called("calculate_hash") == []


@pytest.mark.parametrize("route", ROUTES)
def test_status_list_without_status_list_is_502(client, services, route, caplog):
    services.overrides["status_list"] = make_response(json_body={"detail": "no index available"})

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Status list service returned an invalid response")
    assert API_KEY not in caplog.text
    assert services.called("calculate_hash") == []


@pytest.mark.parametrize("route", ROUTES)
def test_status_list_timeout_is_502(client, services, route, caplog):
    services.overrides["status_list"] = requests.Timeout("read timed out")

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Status list service unavailable")
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("route", ROUTES)
def test_status_list_ok_without_json_is_502(client, services, route):
    services.overrides["status_list"] = make_response(200, text="<html>maintenance</html>")

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Status list service returned an invalid response")


# --- signer ---------------------------------------------------------------------

@pytest.mark.parametrize("route", ROUTES)
def test_signer_error_message_is_returned_as_502(client, services, route, caplog):
    services.overrides["calculate_hash"] = make_response(400, json_body={"message": "Invalid certificate chain"})

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Signing service error: Invalid certificate chain")
    assert "HTTP 400" in caplog.text
    assert services.called("obtain_signed_doc") == []


@pytest.mark.parametrize("route", ROUTES)
def test_signer_timeout_is_502(client, services, route):
    services.overrides["calculate_hash"] = requests.ConnectTimeout("connect timed out")

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Signing service unavailable")


@pytest.mark.parametrize("route", ROUTES)
def test_signer_without_hashes_is_502(client, services, route):
    services.overrides["calculate_hash"] = make_response(json_body={"signature_date": 1700000000000})

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Signing service returned an invalid response")


@pytest.mark.parametrize("route", ROUTES)
def test_signer_without_signed_document_is_502(client, services, fake_db, route):
    services.overrides["obtain_signed_doc"] = make_response(json_body={"message": "ok"})

    response = client.post(route, json=request_body(route))

    assert_error(response, 502, "Signing service returned an invalid response")
    assert fake_db["inserted"] == []


# --- certificate data -----------------------------------------------------------

@pytest.mark.parametrize("route", ROUTES)
def test_intended_use_without_privacy_policy_is_400(client, services, fake_db, route):
    fake_db["intended_use"][0]["privacyPolicy"] = []

    response = client.post(route, json=request_body(route))

    body = assert_error(response, 400)
    assert "has no privacy policy" in body["message"]
    assert services.calls == []  # no status list index taken


def test_policy_of_another_type_is_used_with_a_warning(client, services, fake_db, caplog):
    fake_db["intended_use"][0]["privacyPolicy"] = [
        {"policy_id": 1, "policyURI": "https://rp.test/terms", "type": TERMS},
    ]

    with caplog.at_level(logging.WARNING):
        response = client.post("/intended_use/certificate", json=request_body("/intended_use/certificate"))

    assert response.status_code == 200, response.get_data(as_text=True)
    assert signed_claims(services)["privacy_policy"] == "https://rp.test/terms"
    assert any(r.levelno == logging.WARNING and "Intended Use 11" in r.getMessage() for r in caplog.records)


def remove_support_uri(records):
    records["wrp_service"][0]["supportURI"] = []


def remove_identifier(records):
    records["legal_entity"][0]["identifier"] = []


def unsupported_identifier_type(records):
    records["legal_entity"][0]["identifier"][0]["type"] = "urn:unknown"


def remove_legal_name(records):
    records["legal_entity"][0]["LegalPerson"]["legalName"] = []


def remove_person_data(records):
    records["legal_entity"][0]["LegalPerson"] = None


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("break_records, message", [
    (remove_support_uri, "has no support URI"),
    (remove_identifier, "has no identifier"),
    (unsupported_identifier_type, "identifier type 'urn:unknown' is not supported"),
    (remove_legal_name, "has no legal name"),
    (remove_person_data, "neither legal person nor natural person"),
])
def test_missing_certificate_data_is_400(client, services, fake_db, route, break_records, message):
    break_records(fake_db)

    response = client.post(route, json=request_body(route))

    assert message in assert_error(response, 400)["message"]
    assert services.calls == []


@pytest.mark.parametrize("route", ROUTES)
def test_intended_use_retrieval_failure_is_500(client, services, fake_db, route):
    fake_db["intended_use"] = []

    response = client.post(route, json=request_body(route))

    assert_error(response, 500, "Error retrieving Intended Use 11.")


def test_certificate_not_stored_is_500(client, services, fake_db):
    fake_db["insert_result"] = None

    response = client.post("/intended_use/certificate", json=request_body("/intended_use/certificate"))

    assert_error(response, 500, "Error saving the registration certificate.")


# --- final guard ----------------------------------------------------------------

@pytest.mark.parametrize("route", ROUTES)
def test_unexpected_exception_is_generic_json_500(client, services, monkeypatch, route, caplog):
    def broken(wrp_id):
        raise RuntimeError("database exploded")

    monkeypatch.setattr(routes.db, "get_wrp_id", broken)

    response = client.post(route, json=request_body(route))

    assert_error(response, 500, "Internal server error. Please try again later.")
    [record] = [r for r in caplog.records if r.exc_info]
    assert record.exc_info[0] is RuntimeError
    assert route in record.getMessage()
