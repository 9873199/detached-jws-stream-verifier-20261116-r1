"""Independent cryptographic vectors; run after final API/freeze review."""
import base64
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwcrypto.jwk import JWK
from jwcrypto.common import JWException
from jwcrypto.jwsstream import verify_detached_stream

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=')

@pytest.fixture(scope='module')
def keys():
    secret=b'local-independent-hmac-key-32bytes!'
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    return secret,private,JWK(kty='oct',k=b64(secret).decode()),JWK.from_pem(public)

def signed(body,alg,keys,encoded=True,raw=None,pss_salt=32):
    raw=raw if raw is not None else json.dumps({'alg':alg,**({} if encoded else {'b64':False,'crit':['b64']})},separators=(',',':')).encode()
    protected=b64(raw);message=protected+b'.'+(b64(body) if encoded else body)
    if alg=='HS256':sig=hmac.new(keys[0],message,hashlib.sha256).digest();key=keys[2]
    else:
        pad=padding.PKCS1v15() if alg=='RS256' else padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=pss_salt)
        sig=keys[1].sign(message,pad,hashes.SHA256());key=keys[3]
    return (protected+b'..'+b64(sig)).decode(),key

class ShortStream:
    def __init__(self,data,max_read,pattern=(1,2,5),error_after=None):
        self.data=data;self.offset=0;self.calls=[];self.pattern=pattern;self.max_read=max_read;self.closed=False;self.error_after=error_after
    def read(self,n):
        assert 0<n<=self.max_read,'unbounded read attempted'
        self.calls.append(n)
        if self.error_after is not None and self.offset>=self.error_after:raise OSError('independent-local-read-error')
        count=min(n,self.pattern[(len(self.calls)-1)%len(self.pattern)])
        chunk=self.data[self.offset:self.offset+count];self.offset+=len(chunk);return chunk
    def seek(self,*a):raise AssertionError('seek attempted')
    def close(self):self.closed=True;raise AssertionError('caller stream closed')

@pytest.mark.parametrize('alg',['HS256','RS256','PS256'])
@pytest.mark.parametrize('encoded',[True,False])
@pytest.mark.parametrize('body',[b'',b'\x00\xff\xfehello\xe4\xb8\xad\x00payload-end'])
@pytest.mark.parametrize('chunk',[1,2,4,7])
def test_independent_signature_varied_short_chunks(keys,alg,encoded,body,chunk):
    token,key=signed(body,alg,keys,encoded);stream=ShortStream(body,chunk)
    result=verify_detached_stream(token,key,stream,allowed_algs=[alg],chunk_size=chunk,max_payload_size=len(body))
    assert result.verified and result.payload_size==len(body)
    assert stream.offset==len(body) and not stream.closed and max(stream.calls)<=chunk

@pytest.mark.parametrize('alg',['HS256','RS256','PS256'])
def test_middle_byte_tamper_rejected(keys,alg):
    body=b'start-middle-payload-end';token,key=signed(body,alg,keys)
    corrupt=bytearray(body);corrupt[len(body)//2]^=1
    stream=ShortStream(bytes(corrupt),4)
    with pytest.raises(JWException):verify_detached_stream(token,key,stream,allowed_algs=[alg],chunk_size=4)
    assert not stream.closed

def test_original_protected_encoding_is_authenticated(keys):
    body=b'original-encoding';raw=b'{ "alg" : "HS256" }';token,key=signed(body,'HS256',keys,raw=raw)
    assert verify_detached_stream(token,key,ShortStream(body,3),allowed_algs=['HS256'],chunk_size=3).verified
    parts=token.split('.');parts[0]=b64(b'{"alg":"HS256"}').decode()
    with pytest.raises(JWException):verify_detached_stream('.'.join(parts),key,ShortStream(body,3),allowed_algs=['HS256'],chunk_size=3)

@pytest.mark.parametrize('raw',[
    b'{"alg":"HS256","alg":"HS256"}',
    b'{"alg":"HS256","b64":1}',
    b'{"alg":"HS256","b64":"false"}',
    b'{"alg":"HS256","b64":false}',
    b'{"alg":"HS256","crit":["unknown-extension"]}',
])
def test_ambiguous_or_ununderstood_header_rejected(keys,raw):
    body=b'header-guard';token,key=signed(body,'HS256',keys,raw=raw);stream=ShortStream(body,4)
    with pytest.raises(JWException):verify_detached_stream(token,key,stream,allowed_algs=['HS256'],chunk_size=4)
    assert not stream.closed

def test_algorithm_allowlist_cannot_be_expanded(keys):
    body=b'allowlist';token,key=signed(body,'HS256',keys)
    with pytest.raises(JWException):verify_detached_stream(token,key,ShortStream(body,4),allowed_algs=['RS256'],chunk_size=4)

def test_nonempty_middle_segment_with_external_body_rejected(keys):
    body=b'external';token,key=signed(body,'HS256',keys);parts=token.split('.');parts[1]=b64(body).decode()
    with pytest.raises(JWException):verify_detached_stream('.'.join(parts),key,ShortStream(body,4),allowed_algs=['HS256'],chunk_size=4)

def test_cumulative_limit_stops_further_reads(keys):
    body=b'0123456789abcdefghij';token,key=signed(body,'HS256',keys);stream=ShortStream(body,4,pattern=(3,))
    with pytest.raises(JWException):verify_detached_stream(token,key,stream,allowed_algs=['HS256'],chunk_size=4,max_payload_size=10)
    assert 10<stream.offset<=14 and not stream.closed

def test_read_exception_does_not_publish_or_close(keys):
    body=b'error-after-short-read';token,key=signed(body,'HS256',keys);stream=ShortStream(body,4,pattern=(2,),error_after=4)
    with pytest.raises(OSError,match='independent-local-read-error'):
        verify_detached_stream(token,key,stream,allowed_algs=['HS256'],chunk_size=4)
    assert stream.offset==4 and not stream.closed

def test_ps256_requires_jwa_salt_length(keys):
    body=b'pss-length';token,key=signed(body,'PS256',keys,pss_salt=padding.PSS.MAX_LENGTH)
    with pytest.raises(JWException):verify_detached_stream(token,key,ShortStream(body,4),allowed_algs=['PS256'],chunk_size=4)
