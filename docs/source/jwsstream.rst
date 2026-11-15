Streaming JWS Verification
==========================

The jwsstream module implements memory-bounded verification of compact
detached JWS tokens whose payload is too large to load into memory
(for example multi-gigabyte log archives).

The payload is read exactly once, in bounded-size chunks, from a
caller-supplied read-only, non-seekable binary stream (one-shot
semantics: a consumed stream cannot be re-verified, a fresh stream is
needed for each attempt).  Only the HS256, RS256 and PS256 algorithms
are supported, including the RFC 7797 ``b64=false`` unencoded payload
case; PS256 uses the JWA-mandated salt length (32 bytes).  The caller
must explicitly grant the permitted algorithms and provide a local
:class:`jwcrypto.jwk.JWK`; keys are never fetched from the network.

The caller's stream is never closed.  On any failure (bad signature,
size limit exceeded, stream read error) an exception is raised and no
result object is produced; no :class:`jwcrypto.jws.JWS` object is
involved, so no stale ``is_valid`` state can leak from a previous
success.

Functions
---------

.. autofunction:: jwcrypto.jwsstream.verify_detached_stream

Classes
-------

.. autoclass:: jwcrypto.jwsstream.JWSStreamResult
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jwsstream.STREAMING_SUPPORTED_ALGS

Exceptions
----------

.. autoclass:: jwcrypto.jwsstream.JWSStreamPayloadTooLarge
   :members:
   :show-inheritance:

Examples
--------

Verify a detached compact JWS against a large file::

    >>> from jwcrypto import jwk
    >>> from jwcrypto.jwsstream import verify_detached_stream
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> # token = '<protected>..<signature>' obtained from the archive log
    >>> with open('archive.bin', 'rb') as payload:
    ...     result = verify_detached_stream(
    ...         token, key, stream=payload,
    ...         allowed_algs=['HS256'],
    ...         max_payload_size=10 * 1024 ** 3)
    >>> result.verified
    True
