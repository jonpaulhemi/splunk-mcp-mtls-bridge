# Client certificate mappings, one stanza per mapping. Managed on the app's Configuration page.
# UCC also generates ta_mtls_bridge_account.conf.spec with the same fields, because it names
# the spec for any configuration table "account".
[<name>]
issuer =
* The issuing CA's distinguished name, in RFC 4514 form.
identity_type =
* One of URI, DNS, EMAIL, UPN, IP or CN.
identity_value =
* The identity the client certificate must carry in a field of identity_type.
account =
* The local Splunk account the client acts as.
token =
* Always "******". The account's encrypted MCP token is kept in Splunk's credential store.
token_expiry =
* The date the token expires, as YYYY-MM-DD.
