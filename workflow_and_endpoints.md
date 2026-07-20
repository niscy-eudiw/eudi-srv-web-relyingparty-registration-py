# Workflow

The API uses an authentication flow based on OID4VP and PID verification.

The authentication process works as follows:

1. Start the authentication flow and obtain a QR Code and `presentation_id`
2. Wait for PID authorization validation
3. Retrieve the authenticated user's `hash_pid`
4. Use the `hash_pid` in authenticated endpoints

---

## Authentication Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/authentication` | Start authentication flow and generate QR Code |
| GET | `/pid_authorization` | Validate PID authorization status |
| GET / POST | `/getpidoid4vp` | Retrieve PID data and obtain `hash_pid` |

---

## Authentication Flow Description

### 1. `/authentication`

Starts the authentication process.

Returns:
- QR Code for wallet authentication
- `presentation_id`

The QR Code must be scanned by the user's wallet application.

---

### 2. `/pid_authorization`

Checks whether the PID authorization was completed successfully.
This endpoint waits for the authentication result and validates the received PID authorization.

---

### 3. `/getpidoid4vp`

Retrieves the PID data obtained through the OID4VP flow.

Returns:
- User PID information
- Generated `hash_pid`

The returned `hash_pid` must be used in authenticated API requests.

---

## Example Authenticated Request

```json
{
  "hash_pid": "abc123hash"
}
```

# Endpoints
---

## Identifier Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/identifier/create` | Create identifiers |
| POST | `/identifier/list` | Retrieve identifiers |

---

## Law Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/law/create` | Create laws |
| POST | `/law/list` | Retrieve laws |

---

## Natural Person Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/natural_person/create` | Create natural persons |
| POST | `/natural_person/list` | Retrieve natural persons |

---

## Legal Person Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/legal_person/create` | Create legal persons |
| POST | `/legal_person/list` | Retrieve legal persons |
| POST | `/legal_person/update_law` | Associate laws with legal persons |
| POST | `/legal_person/remove_law` | Remove laws from legal persons |

---

## Legal Entity Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/legal_entity/create` | Create legal entities |
| POST | `/legal_entity/list` | Retrieve legal entities |
| POST | `/legal_entity/update_identifier` | Associate identifiers |
| POST | `/legal_entity/remove_identifier` | Remove identifiers |

---

## Policy Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/policy/create` | Create policies |
| POST | `/policy/list` | Retrieve policies |

---

## Provider Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/provider/create` | Create providers |
| POST | `/provider/list` | Retrieve providers |
| POST | `/provider/update_policy` | Associate policies with providers |
| POST | `/provider/remove_policy` | Remove policies from providers |

---

## Credential Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/credential/create` | Create credentials |
| POST | `/credential/list` | Retrieve credentials |
| POST | `/list_claim` | Retrieve claims |

---

## Intended Use Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/intended_use/create` | Create intended uses |
| POST | `/intended_use/list` | Retrieve intended uses |
| POST | `/intended_use/update_credential` | Associate credentials |
| POST | `/intended_use/update_policy` | Associate policies |
| POST | `/intended_use/remove_credential` | Remove credentials |
| POST | `/intended_use/remove_policy` | Remove policies |

---

## Provided Attestation Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/provided_attestation/create` | Create provided attestations |
| POST | `/provided_attestation/list` | Retrieve provided attestations |

---

## Supervisory Authority Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/supervisory_authority/create` | Create supervisory authorities |
| POST | `/supervisory_authority/list` | Retrieve supervisory authorities |

---

## Wallet Relying Party Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/wallet_rp/create` | Create Wallet Relying Parties |
| POST | `/wallet_rp/list` | Retrieve Wallet Relying Parties |
| POST | `/wallet_rp/update_intended_use` | Associate intended uses |
| POST | `/wallet_rp/update_provided_attestation` | Associate provided attestations |
| POST | `/wallet_rp/update_uses_intermediary` | Associate intermediary WRPs |
| POST | `/wallet_rp/remove_intended_use` | Remove intended uses |
| POST | `/wallet_rp/remove_provided_attestation` | Remove provided attestations |
| POST | `/wallet_rp/remove_uses_intermediary` | Remove intermediary WRPs |

---

## Public Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/wrp` | Search Wallet Relying Parties |
| GET | `/wrp/<identifier>` | Retrieve Wallet Relying Party by identifier |
| GET | `/wrp/check-intended-use` | Validate intended use compatibility |

---

## Utility Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/list_full_info` | Retrieve complete hierarchical user information |

## Certificates

| Method | Endpoint | Description |
|---|---|---|
| POST | `/intended_use/certificate` | Generate Intended Use Registration Certificate |
| POST | `/wallet_rp/certificate` | Generate Wallet Relying Party Access Certificate |
