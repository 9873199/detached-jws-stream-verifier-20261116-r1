"""Reviewer demonstration using the unchanged frozen verifier."""
import base64,hashlib,hmac,json
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from jwcrypto.jwk import JWK
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwsstream import verify_detached_stream,JWSStreamPayloadTooLarge

def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=')
class Body:
    def __init__(self,data):self.data=data;self.offset=0;self.reads=0
    def read(self,n):
        assert 0<n<=4
        self.reads+=1;chunk=self.data[self.offset:self.offset+min(3,n)];self.offset+=len(chunk);return chunk
secret=b'local-demo-key-for-hmac-at-least-32bytes'
private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
octkey=JWK(kty='oct',k=b64(secret).decode());rsakey=JWK.from_pem(public)
body=b'archive chunk: \x00\xff, content verified'
print('Archive signature verification - fresh local run')
for alg in ('HS256','RS256','PS256'):
    protected=b64(json.dumps({'alg':alg},separators=(',',':')).encode());message=protected+b'.'+b64(body)
    if alg=='HS256':sig=hmac.new(secret,message,hashlib.sha256).digest();key=octkey
    else:
        pad=padding.PKCS1v15() if alg=='RS256' else padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32)
        sig=private.sign(message,pad,hashes.SHA256());key=rsakey
    token=(protected+b'..'+b64(sig)).decode();stream=Body(body)
    result=verify_detached_stream(token,key,stream,allowed_algs=[alg],chunk_size=4,max_payload_size=len(body))
    assert result.verified and result.payload_size==len(body)
    print(alg+': verified; '+str(result.payload_size)+' bytes; '+str(stream.reads)+' bounded reads')
    if alg=='HS256':hmac_token=token
try:verify_detached_stream(hmac_token,octkey,Body(body+b'!'),allowed_algs=['HS256'],chunk_size=4)
except InvalidJWSSignature:print('Changed archive: REJECTED (signature mismatch)')
else:raise AssertionError('changed body accepted')
stream=Body(body)
try:verify_detached_stream(hmac_token,octkey,stream,allowed_algs=['HS256'],chunk_size=4,max_payload_size=8)
except JWSStreamPayloadTooLarge:print('8-byte limit: REJECTED after '+str(stream.offset)+' bytes; reading stopped')
else:raise AssertionError('size limit bypassed')
print('All displayed checks completed against the frozen library.')
