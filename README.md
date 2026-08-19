# dtls

DTLS 1.2 in pure PHP. No FFI, no `dlopen`, no native libraries.

PHP has no native DTLS, so WebRTC stacks written in PHP reach for FFI and `dlopen` OpenSSL at
runtime. That fails outright on a statically linked musl build, because static musl has no working
`dlopen` - which is what blocks NetherNet on Android.

Every primitive DTLS needs is already in `ext-openssl`, statically compiled into the binary:
ECDHE on P-256 via `openssl_pkey_derive()`, the TLS 1.2 PRF via `hash_hmac()`, AES-GCM via
`openssl_encrypt()`, and ECDSA via `openssl_sign()`. Only the protocol itself was missing. That is
what this package is.

## Usage

```
composer require altayofficial/dtls
```

The connection owns no socket. Outbound datagrams go to a callback and inbound ones are pushed in,
so it sits on an ICE transport as readily as on a UDP socket.

```php
use altay\dtls\Certificate;
use altay\dtls\Connection;

$certificate = Certificate::generate();

$connection = Connection::client($certificate, function(string $datagram) use ($socket) : void{
    fwrite($socket, $datagram);
});

$connection->onEstablished(function() use ($connection) : void{
    $connection->send("hello");
});

$connection->onApplicationData(function(string $data) : void{
    echo $data;
});

$connection->start();

while(true){
    $datagram = fread($socket, 65535);
    if($datagram !== false && $datagram !== ""){
        $connection->handle($datagram);
    }else{
        //retransmits the last flight when the peer goes quiet
        $connection->handleTimeout();
    }
}
```

`Connection::server()` takes the other role. A server answers the first ClientHello with a
HelloVerifyRequest and only keeps state once the cookie comes back, so an unverified peer cannot
make it allocate anything.

## What is implemented

| | |
| --- | --- |
| Version | DTLS 1.2 |
| Cipher suite | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` |
| Curve | P-256 |
| Roles | client and server |
| Extended master secret | RFC 7627, offered and honoured |
| Authentication | mutual, by certificate fingerprint |
| Cookies | HelloVerifyRequest, stateless until verified |
| Reliability | handshake fragmentation, reassembly, retransmission with backoff |
| Replay | 64 entry sliding window |

## Fingerprints, not chains

WebRTC has no PKI. The offer and answer carry an `a=fingerprint` line, and a peer is trusted
exactly when the certificate it presents hashes to the value that arrived over signalling. So
nothing here builds or validates a chain - compare `getPeerFingerprint()` against the SDP value
and reject on mismatch.

```php
if(!hash_equals($fingerprintFromSdp, $connection->getPeerFingerprint())){
    throw new RuntimeException("peer is not who signalling said it was");
}
```

The handshake itself already proves the peer holds the private key for that certificate, through
the signature on ServerKeyExchange and CertificateVerify.

## Testing

```
composer test
composer analyse
```

The unit tests drive a client and a server against each other in memory, including a dropped
flight and duplicated datagrams. Agreeing with itself is a weak claim though, so
`tests/interop.php` runs against the OpenSSL command line tools in both roles:

```
# our client against a real DTLS server
openssl s_server -dtls1_2 -listen -accept 4444 -cert cert.pem -key key.pem
php tests/interop.php client 4444

# our server against a real DTLS client
php tests/interop.php server 4444
openssl s_client -dtls1_2 -connect 127.0.0.1:4444
```

## Requirements

PHP 8.1+, `ext-openssl`, `ext-hash`. Both are compiled into the PHP binaries Altay ships, which is
the entire point - there is nothing to load at runtime.

## Scope

This is a datachannel transport, so there is no SRTP, no key export for media, and no
renegotiation. Session resumption is not implemented either. The suite list is deliberately one
entry long: it is what libwebrtc negotiates, and every extra option is more code that has to be
correct.
