import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
from urllib.parse import parse_qs, quote
import base64
from Cryptodome.Signature import pss
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import ECC
from Cryptodome import Random
from Cryptodome.IO import PEM
from Cryptodome.IO import PKCS8
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Util.asn1 import DerOctetString
from Cryptodome.Util.asn1 import DerBitString
from Cryptodome.Util.asn1 import DerSequence
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
mgf512 = lambda x, y: MGF1(x, y, SHA512)

structuredFields = {
    'accept': 'list',
    'accept-encoding': 'list',
    'accept-language': 'list',
    'accept-patch': 'list',
    'accept-ranges': 'list',
    'access-control-allow-credentials': 'item',
    'access-control-allow-headers': 'list',
    'access-control-allow-methods': 'list',
    'access-control-allow-origin': 'item',
    'access-control-expose-headers': 'list',
    'access-control-max-age': 'item',
    'access-control-request-headers': 'list',
    'access-control-request-method': 'item',
    'age': 'item',
    'allow': 'list',
    'alpn': 'list',
    'alt-svc': 'dict',
    'alt-used': 'item',
    'cache-control': 'dict',
    'connection': 'list',
    'content-encoding': 'list',
    'content-language': 'list',
    'content-length': 'list',
    'content-type': 'item',
    'cross-origin-resource-policy': 'item',
    'expect': 'item',
    'expect-ct': 'dict',
    'host': 'item',
    'keep-alive': 'dict',
    'origin': 'item',
    'pragma': 'dict',
    'prefer': 'dict',
    'preference-applied': 'dict',
    'retry-after': 'item',
    'surrogate-control': 'dict',
    'te': 'list',
    'timing-allow-origin': 'list',
    'trailer': 'list',
    'transfer-encoding': 'list',
    'vary': 'list',
    'x-content-type-options': 'item',
    'x-frame-options': 'item',
    'x-xss-protection': 'list',
    "cache-status": "list",
    "proxy-status": "list",
    "variant-key": "list",
    "variants": "dict",
    "signature": "dict",
    "signature-input": "dict",
    "priority": "dict",
    "x-dictionary": "dict",
    "x-list": "list",
    "x-list-a": "list",
    "x-list-b": "list",
    "accept-ch": "list",
    "example-list": "list",
    "example-dict": "dict",
    "example-integer": "item",
    "example-decimal": "item",
    "example-string": "item",
    "example-token": "item",
    "example-bytesequence": "item",
    "example-boolean": "item",
    "cdn-cache-control": "dict"
}

def parse_components(msg, req = False):
    p = HttpParser()
    p.execute(msg, len(msg))
    
    response = {}
    
    response['fields'] = []
    for h in p.get_headers():
        cid = http_sfv.Item(h.lower())
        f = {
            'id': cid.value,
            'cid': str(cid),
            'val': p.get_headers()[h] # Note: this normalizes the header value for us
        }
        response['fields'].append(f)

        # see if this is a known structured field
        if h and h.lower() in structuredFields:
            if structuredFields[h.lower()] == 'dict':
                sv = http_sfv.Dictionary()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                for k in sv:
                    cid = http_sfv.Item(h.lower())
                    cid.params['key'] = k
                    f = {
                            'id': cid.value,
                            'cid': str(cid),
                            'key': k,
                            'val': str(sv[k])
                    }
                    response['fields'].append(f)
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                f = {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                }
                response['fields'].append(f)
                
            elif structuredFields[h.lower()] == 'list':
                sv = http_sfv.List()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                f = {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                }
                response['fields'].append(f)
                
            elif structuredFields[h.lower()] == 'item':
                sv = http_sfv.Item()
                sv.parse(p.get_headers()[h].encode('utf-8'))
        
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                f = {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                }
                response['fields'].append(f)

    if req:
        for f in response['fields']:
            i = http_sfv.Item()
            i.parse(f['cid'].encode('utf-8'))
            i.params['req'] = True
            f['req'] = True
            f['cid'] = str(i)


    if p.get_status_code():
        # response
        response['derived'] = [
            {
                'id': '@status',
                'cid': str(http_sfv.Item('@status')),
                'val': str(p.get_status_code())
            }
        ]
    else:
        # request
        response['derived'] = [
            {
                'id': '@method',
                'cid': str(http_sfv.Item('@method')),
                'val': p.get_method()
            },
            {
                'id': '@target-uri',
                'cid': str(http_sfv.Item('@target-uri')),
                'val': 
                'https://' # TODO: this always assumes an HTTP connection for demo purposes
                    + p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
                    + p.get_url()
            },
            {
                'id': '@authority',
                'cid': str(http_sfv.Item('@authority')),
                'val':  p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
            },
            {
                'id': '@scheme',
                'cid': str(http_sfv.Item('@scheme')),
                'val':  'https' # TODO: this always assumes an HTTPS connection for demo purposes
            },
            {
                'id': '@request-target',
                'cid': str(http_sfv.Item('@request-target')),
                'val':  p.get_url()
            },
            {
                'id': '@path',
                'cid': str(http_sfv.Item('@path')),
                'val':  p.get_path()
            },
            {
                'id': '@query',
                'cid': str(http_sfv.Item('@query')),
                'val':  '?' + p.get_query_string()
            }
        ]

        qs = parse_qs(p.get_query_string())
        for q in qs:
            v = qs[q]
            # multiple values are undefined
            if len(v) == 1:
                cid = http_sfv.Item('@query-param')
                name = quote(q.encode('utf-8')) # name is quoted version, after parsing
                cid.params['name'] = name
                response['derived'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'name': name,
                        'val': quote(v[0].encode('utf-8')) # value is the quoted version, after parsing
                    }
                )

        if req:
            for d in response['derived']:
                i = http_sfv.Item()
                i.parse(d['cid'].encode('utf-8'))
                i.params['req'] = True
                d['req'] = True
                d['cid'] = str(i)

    if 'signature-input' in p.get_headers():
        # existing signatures, parse the values
        siginputheader = http_sfv.Dictionary()
        siginputheader.parse(p.get_headers()['signature-input'].encode('utf-8'))
        
        sigheader = http_sfv.Dictionary()
        sigheader.parse(p.get_headers()['signature'].encode('utf-8'))
        
        siginputs = {}
        for (k,v) in siginputheader.items():
            
            existingComponents = []
            for c in v:
                cc = { # holder object
                    'id': c.value,
                    'cid': str(c)
                }
                if not cc['id'].startswith('@'):
                    # it's a header, try to get the existing value
                    fields = (f for f in response['fields'] if f['id'] == cc['id'])
                    if 'sf' in c.params:
                        cc['sf'] = c.params['sf']
                        cc['val'] = next((f['val'] for f in fields if 'sf' in f and f['sf'] == c.params['sf']), None)
                    elif 'key' in c.params:
                        cc['key'] = c.params['key']
                        cc['val'] = next((f['val'] for f in fields if 'key' in f and f['key'] == c.params['key']), None)
                    else:
                        cc['val'] = next((f['val'] for f in fields if ('key' not in f and 'sf' not in f)), None)
                else:
                    # it's derived
                    derived = (d for d in response['derived'] if d['id'] == cc['id'])
                    
                    if cc['id'] == '@query-param' and 'name' in c.params:
                        cc['name'] = c.params['name']
                        cc['val'] = next((d['val'] for d in derived if d['name'] == c.params['name']), None)
                    else:
                        cc['val'] = next((d['val'] for d in derived if ('name' not in d)), None)

                existingComponents.append(cc)
            
            siginput = {
                'coveredComponents': existingComponents,
                'params': {p:pv for (p,pv) in v.params.items()},
                'value': str(v),
                'signature': str(sigheader[k])
            }
            siginputs[k] = siginput
            
        response['inputSignatures'] = siginputs

    # process the body
    body = p.recv_body()
    if body:
        response['body'] = body.decode('utf-8')

    return response
    
def add_content_digest(components, alg='sha-512'):
    if 'body' in components:
        if alg == 'sha-512':
            h = SHA512.new(components['body'].encode('utf-8'))
        elif alg == 'sha-256':
            h = SHA256.new(components['body'].encode('utf-8'))
        else:
            # unknown alg, skip it
            return components
        dv = http_sfv.Item(h.digest())
        cd = http_sfv.Dictionary()
        cd[alg] = dv
        
        cid = http_sfv.Item('Content-Digest'.lower())
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'val': str(cd)
            }
        )
        
        # key with algorithm
        cid = http_sfv.Item('Content-Digest'.lower())
        cid.params['key'] = alg
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'key': alg,
                'val': str(dv)
            }
        )
        
        # structured field strict serialization
        cid = http_sfv.Item('Content-Digest'.lower())
        cid.params['sf'] = True
        components['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'sf': True,
                'val': str(cd)
            }
        )
        
        return components
    else:
        return components

def generate_base(components, coveredComponents, params, related = []):
    sigparams = http_sfv.InnerList()
    base = ''

    for cc in coveredComponents:
        if 'req' in cc:
            src = related
        else:
            src = components
        c = cc['id']
        if not c.startswith('@'):
            # it's a header
            i = http_sfv.Item(c.lower())
            if 'req' in cc:
                i.params['req'] = True
            if 'key' in cc:
                # try a dictionary header value
                i.params['key'] = cc['key']
                comp = next((x for x in src['fields'] if 'key' in x and x['id'] == c and x['key'] == cc['key']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            elif 'sf' in cc:
                i.params['sf'] = True
                comp = next((x for x in src['fields'] if 'sf' in x and x['id'] == c and x['sf'] == cc['sf']), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in src['fields'] if x['id'] == c), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
        else:
            # it's a derived value
            i = http_sfv.Item(c)
            if 'req' in cc:
                i.params['req'] = True
            if 'name' in cc and c == '@query-param':
                # query-param has a 'name' field
                i.params['name'] = cc['name']
                comp = next((x for x in src['derived'] if 'name' in x and x['id'] == c and x['name'] == cc['name']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in src['derived'] if x['id'] == c), None)

                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"

    for pn in params:
        sigparams.params[pn] = params[pn]

    sigparamstr = ''
    sigparamstr += str(http_sfv.Item("@signature-params")) # never any parameters
    sigparamstr += ': '
    sigparamstr += str(sigparams)
    
    base += sigparamstr
    
    response = {
        'signatureInput': base,
        'signatureParams': str(sigparams)
    }
    
    return response
