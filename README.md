# HTTP Message Signatures

This library implements HTTP Message Signatures. The underlying crypto is provided by PyCryptodomex.

Pypi Page: <https://pypi.org/project/httpsigpy/>

Usage:

``` python
from httpsig import *
```

## Signing

To sign an HTTP message, first it has to be parsed into its message components:

``` python
msg = event['body'].encode('utf-8')
components = parse_components(msg)
```

This provides a data structure with each possible message component indexed by its name, identifier, and value.

To create the signature input, pass in the parsed components structure as well as a list of components to sign, with the signature parameters:

``` python
siginput = generate_input(
    components, 
    ( # covered components list
        { 'id': "@method" }, 
        { 'id': "@authority" },
        { 'id': "@path" },
        { 'id': "content-digest" },
        { 'id': "content-length" },
        { 'id': "content-type" }
    ),
    {
        'created': 1618884473,
        'keyid': 'test-key-rsa-pss'
    }
)

base = siginput['signatureInput']
sigparams = siginput['signatureParams']
```

This outputs a `base` string that can be passed to the signer.

``` python
key = RSA.import_key(PKCS8.unwrap(PEM.decode(rsaTestKeyPssPrivate)[0])[1])

h = SHA512.new(base.encode('utf-8'))
signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

signed = http_sfv.Item(signer.sign(h))
```

## Verify

To verify an HTTP message, first it has to be parsed into its message components:

``` python
msg = event['body'].encode('utf-8')
components = parse_components(msg)
```

This provides a data structure with each possible message component indexed by its name, identifier, and value.

To create the signature input, pass in the parsed components structure as well as a list of components to sign, and the signature parameters.

``` python
siginput = generate_input(
    components, 
    ( # covered components list
        { 'id': "@method" }, 
        { 'id': "@authority" },
        { 'id': "@path" },
        { 'id': "content-digest" },
        { 'id': "content-length" },
        { 'id': "content-type" }
    ),
    {
        'created': 1618884473,
        'keyid': 'test-key-rsa-pss'
    }
)
```

This can be passed to the verifier function:

``` python
h = SHA512.new(base.encode('utf-8'))

pubKey = RSA.import_key(rsaTestKeyPssPublic)
verifier = pss.new(pubKey, mask_func=mgf512, salt_bytes=64)

try:
    verified = verifier.verify(h, signed.value)
    print('> YES!')
except (ValueError, TypeError):
    print('> NO!')
```
