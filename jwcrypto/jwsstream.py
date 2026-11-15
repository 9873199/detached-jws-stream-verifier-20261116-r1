# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Streaming verification of compact detached JWS tokens.

This module provides a verification path for JWS tokens whose payload
is too large to be loaded into memory (for example multi-gigabyte log
archives).  The payload is read exactly once, in bounded-size chunks,
from a caller-supplied read-only, non-seekable binary stream, and the
signature is checked incrementally.  The payload is never buffered in
full and never exposed by this module: a successful call returns an
immutable :class:`JWSStreamResult` that carries only metadata about the
verification, not the verified bytes.

Scope and one-shot semantics:

* Only the compact serialization is accepted, with a single signature.
* Only the HS256, RS256 and PS256 algorithms (RFC 7518) are supported,
  including the RFC 7797 ``b64=false`` unencoded-payload case.  PS256
  is verified with the JWA-mandated salt length (the SHA-256 output
  size, 32 bytes).
* The stream is consumed exactly once, in a single pass; there is no
  way to rewind or re-verify without the caller supplying a fresh
  stream.  Each ``verify_detached_stream()`` call is independent and
  keeps no reusable state.
* The caller's stream is never closed by this module.
* Nothing is published on failure: any verification failure, payload
  size overflow, or stream read error raises and no result object is
  produced.  No :class:`jwcrypto.jws.JWS` object is touched, so no
  stale ``is_valid`` state can survive a failed attempt.
"""

import hashlib
import hmac
import json
from base64 import urlsafe_b64encode
from collections import namedtuple
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from jwcrypto import jwa
from jwcrypto.common import JWException, base64url_decode
from jwcrypto.common import InvalidJWEKeyLength
from jwcrypto.jwk import JWK
from jwcrypto.jws import InvalidJWSObject, InvalidJWSOperation
from jwcrypto.jws import InvalidJWSSignature

STREAMING_SUPPORTED_ALGS = frozenset(['HS256', 'RS256', 'PS256'])
"""Algorithms supported by the streaming verifier."""

# Critical header extensions understood by this module.  Anything else
# listed in "crit" is rejected.
_UNDERSTOOD_CRIT = frozenset(['b64'])

_DEFAULT_CHUNK_SIZE = 64 * 1024


class JWSStreamPayloadTooLarge(JWException):
    """The detached payload exceeded the caller-provided size limit.

    Raised as soon as the cumulative number of bytes read from the
    payload stream exceeds ``max_payload_size``; the stream is not
    read any further.
    """

    def __init__(self, message=None):
        msg = message if message else 'Detached payload size limit exceeded'
        super(JWSStreamPayloadTooLarge, self).__init__(msg)


class JWSStreamResult(namedtuple('JWSStreamResult',
                                 ['alg', 'protected_header',
                                  'payload_size'])):
    """Immutable result of a successful streaming JWS verification.

    An instance is only ever produced after the signature has been
    fully verified, so ``verified`` is always True.  The verified
    payload bytes are deliberately not included; they were consumed
    from the caller's stream during verification.

    .. attribute:: alg

       The verified ``alg`` header value (a member of
       :data:`STREAMING_SUPPORTED_ALGS`).

    .. attribute:: protected_header

       A read-only mapping with the decoded protected header.

    .. attribute:: payload_size

       The number of payload bytes read from the stream (the raw
       payload, before any base64url encoding).
    """

    __slots__ = ()

    @property
    def verified(self):
        """Always True; a result object exists only after success."""
        return True


def _reject_duplicate_members(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise InvalidJWSObject(
                'Duplicate JSON member "%s" in protected header' % k)
        obj[k] = v
    return obj


def _parse_compact(token):
    if isinstance(token, str):
        token = token.encode('utf-8')
    if not isinstance(token, (bytes, bytearray)):
        raise TypeError('token must be a str or bytes')
    parts = bytes(token).split(b'.')
    if len(parts) != 3:
        raise InvalidJWSObject('Unrecognized representation')
    protected_b64, payload_seg, sig_b64 = parts
    if len(protected_b64) == 0:
        raise InvalidJWSObject('Missing protected header')
    try:
        protected_raw = base64url_decode(protected_b64.decode('utf-8'))
        header = json.loads(protected_raw.decode('utf-8'),
                            object_pairs_hook=_reject_duplicate_members)
    except InvalidJWSObject:
        raise
    except Exception as e:
        raise InvalidJWSObject('Invalid protected header') from e
    if not isinstance(header, dict):
        raise InvalidJWSObject('Invalid Protected header')
    try:
        signature = base64url_decode(sig_b64.decode('utf-8'))
    except Exception as e:
        raise InvalidJWSObject('Invalid signature encoding') from e
    return protected_b64, payload_seg, header, signature


def _check_header(header, allowed_algs):
    if allowed_algs is None:
        raise ValueError('allowed_algs must be explicitly provided')
    if not isinstance(allowed_algs, (list, tuple, set, frozenset)):
        raise TypeError('allowed_algs must be a list of algorithm names')
    unknown = set(allowed_algs) - STREAMING_SUPPORTED_ALGS
    if unknown:
        raise ValueError('Unsupported algorithms for streaming '
                         'verification: %s' % repr(sorted(unknown)))
    if not allowed_algs:
        raise ValueError('allowed_algs must not be empty')

    alg = header.get('alg')
    if not isinstance(alg, str):
        raise InvalidJWSObject('Missing or invalid "alg" header')
    if alg not in allowed_algs:
        raise InvalidJWSOperation('Algorithm not allowed')

    b64 = header.get('b64', True)
    if not isinstance(b64, bool):
        raise InvalidJWSObject('b64 header must be boolean')

    crit = header.get('crit')
    if crit is not None:
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidJWSObject('"crit" header must be a non-empty list')
        for name in crit:
            if not isinstance(name, str):
                raise InvalidJWSObject('Critical header name must be a '
                                       'string')
            if name not in header:
                raise InvalidJWSObject('Missing critical header '
                                       '"%s"' % name)
            if name not in _UNDERSTOOD_CRIT:
                raise InvalidJWSObject('Unsupported critical header '
                                       '"%s"' % name)

    # RFC 7797: the "b64" header parameter must always be critical;
    # in particular b64=false is rejected unless declared in "crit".
    if 'b64' in header and (crit is None or 'b64' not in crit):
        raise InvalidJWSObject('b64 header must always be critical')

    return alg, b64


class _HMACVerifier:
    def __init__(self, key):
        skey = base64url_decode(key.get_op_key('verify'))
        if jwa.default_enforce_hmac_key_length and len(skey) * 8 < 256:
            raise InvalidJWEKeyLength(256, len(skey) * 8)
        self._mac = hmac.new(skey, digestmod=hashlib.sha256)

    def update(self, data):
        self._mac.update(data)

    def verify(self, signature):
        if not hmac.compare_digest(self._mac.digest(), signature):
            raise InvalidJWSSignature('Verification failed')


class _RSAVerifier:
    def __init__(self, key, padfn):
        self._pkey = key.get_op_key('verify')
        self._padfn = padfn
        self._hash = hashlib.sha256()

    def update(self, data):
        self._hash.update(data)

    def verify(self, signature):
        try:
            self._pkey.verify(signature, self._hash.digest(), self._padfn,
                              asym_utils.Prehashed(hashes.SHA256()))
        except InvalidSignature as e:
            raise InvalidJWSSignature('Verification failed') from e


def _make_verifier(alg, key):
    if alg == 'HS256':
        if key.get('kty') != 'oct':
            raise InvalidJWSOperation('HS256 requires an "oct" key')
        return _HMACVerifier(key)
    if key.get('kty') != 'RSA':
        raise InvalidJWSOperation('%s requires an "RSA" key' % alg)
    if alg == 'RS256':
        padfn = padding.PKCS1v15()
    else:  # PS256: JWA mandates salt length == hash output size
        padfn = padding.PSS(padding.MGF1(hashes.SHA256()),
                            hashes.SHA256().digest_size)
    return _RSAVerifier(key, padfn)


class _B64UrlEncoder:
    """Incremental base64url (no padding) encoder.

    Keeps the 1-2 byte remainder across chunks so that the encoded
    output is exactly the base64url encoding of the whole payload,
    not a concatenation of individually padded chunk encodings.
    """

    def __init__(self, update):
        self._update = update
        self._carry = b''

    def feed(self, chunk):
        data = self._carry + chunk
        whole = len(data) - (len(data) % 3)
        if whole:
            self._update(urlsafe_b64encode(data[:whole]))
        self._carry = data[whole:]

    def flush(self):
        if self._carry:
            self._update(urlsafe_b64encode(self._carry).rstrip(b'='))
            self._carry = b''


def verify_detached_stream(token, key, stream=None, allowed_algs=None,
                           chunk_size=_DEFAULT_CHUNK_SIZE,
                           max_payload_size=None):
    """Verifies a compact detached JWS against a payload stream.

    The payload is read from ``stream`` exactly once, in chunks of at
    most ``chunk_size`` bytes, and is never buffered in full.  The
    original encoding of the protected header (as it appears in the
    token) is used as part of the signature input.

    :param token: The JWS token in compact serialization (str or
        bytes).  The payload segment must be empty when ``stream``
        is provided.
    :param key: A local :class:`jwcrypto.jwk.JWK` verification key.
        Keys are never fetched from the network (``jku``/``x5u``
        headers are ignored).
    :param stream: A read-only binary file-like object providing the
        detached payload.  It is read once, is never seek()ed and is
        never closed by this function.  Short reads are tolerated.
    :param allowed_algs: Mandatory list of permitted algorithms; each
        entry must be one of 'HS256', 'RS256', 'PS256'.  The token's
        ``alg`` header must be in this list; it cannot widen the
        granted permission.
    :param chunk_size: Maximum number of bytes read per read() call.
    :param max_payload_size: Optional cumulative payload size limit in
        bytes.  As soon as more bytes than this have been read,
        :class:`JWSStreamPayloadTooLarge` is raised and the stream is
        not read further.

    :raises InvalidJWSObject: if the token or its protected header is
        malformed (including duplicate JSON members, a non-boolean
        ``b64`` value, or ``b64=false`` not declared critical).
    :raises InvalidJWSOperation: if the algorithm is not allowed, or a
        detached payload stream is provided together with a non-empty
        token payload segment.
    :raises InvalidJWSSignature: if the signature does not verify.
    :raises JWSStreamPayloadTooLarge: if the payload exceeds
        ``max_payload_size``.
    :raises ValueError: on invalid arguments.

    :return: An immutable :class:`JWSStreamResult`.  No result is
        produced unless verification succeeds.
    :rtype: JWSStreamResult
    """
    if not isinstance(key, JWK):
        raise ValueError('key is not a JWK object')
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError('chunk_size must be a positive integer')
    if max_payload_size is not None and max_payload_size < 0:
        raise ValueError('max_payload_size must be non-negative')

    protected_b64, payload_seg, header, signature = _parse_compact(token)
    alg, b64 = _check_header(header, allowed_algs)

    if payload_seg and stream is not None:
        raise InvalidJWSOperation('Object Payload present but Detached '
                                  'Payload stream provided')
    if not payload_seg and stream is None:
        raise InvalidJWSOperation('A detached payload stream is required')

    verifier = _make_verifier(alg, key)
    verifier.update(protected_b64)
    verifier.update(b'.')

    if payload_seg:
        # Embedded payload: the segment itself is the encoded payload.
        verifier.update(payload_seg)
        if b64:
            try:
                payload_size = len(
                    base64url_decode(payload_seg.decode('utf-8')))
            except Exception as e:
                raise InvalidJWSObject('Invalid payload encoding') from e
        else:
            payload_size = len(payload_seg)
    else:
        if not hasattr(stream, 'read'):
            raise TypeError('stream must be a readable file-like object')
        feed = verifier.update
        encoder = None
        if b64:
            encoder = _B64UrlEncoder(verifier.update)
            feed = encoder.feed
        payload_size = 0
        while True:
            chunk = stream.read(chunk_size)
            if chunk is None:
                raise InvalidJWSOperation(
                    'Payload stream returned None instead of bytes')
            if isinstance(chunk, str):
                raise TypeError('Payload stream must return bytes, not str')
            if len(chunk) == 0:
                break
            payload_size += len(chunk)
            if max_payload_size is not None and \
                    payload_size > max_payload_size:
                raise JWSStreamPayloadTooLarge(
                    'Detached payload exceeds limit of %d bytes'
                    % max_payload_size)
            feed(chunk)
        if encoder is not None:
            encoder.flush()

    verifier.verify(signature)

    return JWSStreamResult(
        alg=alg,
        protected_header=MappingProxyType(dict(header)),
        payload_size=payload_size)
