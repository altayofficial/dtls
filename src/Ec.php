<?php

declare(strict_types=1);

namespace altay\dtls;

use altay\dtls\Exception\DtlsException;
use OpenSSLAsymmetricKey;

/**
 * Conversions between the raw EC points TLS puts on the wire and the key objects ext-openssl
 * works with.
 *
 * TLS carries a P-256 public key as an uncompressed point, 0x04 followed by the two 32 byte
 * coordinates. ext-openssl only parses SubjectPublicKeyInfo, so the point is wrapped in the
 * fixed DER header for id-ecPublicKey over prime256v1 before being handed over.
 */
final class Ec{

	//SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (65 bytes) }
	private const P256_SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

	private const COORDINATE_LENGTH = 32;

	private function __construct(){
		//static only
	}

	public static function pointOf(OpenSSLAsymmetricKey $key) : string{
		$details = openssl_pkey_get_details($key);
		if($details === false || !isset($details["ec"]["x"], $details["ec"]["y"])){
			throw new DtlsException("not an EC key");
		}

		return "\x04"
			. str_pad($details["ec"]["x"], self::COORDINATE_LENGTH, "\x00", STR_PAD_LEFT)
			. str_pad($details["ec"]["y"], self::COORDINATE_LENGTH, "\x00", STR_PAD_LEFT);
	}

	public static function publicKeyFromPoint(string $point) : OpenSSLAsymmetricKey{
		if(strlen($point) !== 1 + 2 * self::COORDINATE_LENGTH || $point[0] !== "\x04"){
			throw new DtlsException("expected an uncompressed P-256 point");
		}

		$pem = "-----BEGIN PUBLIC KEY-----\n"
			. chunk_split(base64_encode(self::P256_SPKI_PREFIX . $point), 64, "\n")
			. "-----END PUBLIC KEY-----\n";

		$key = openssl_pkey_get_public($pem);
		if($key === false){
			throw new DtlsException("could not parse the peer's EC point");
		}

		return $key;
	}

	public static function derive(string $peerPoint, OpenSSLAsymmetricKey $privateKey) : string{
		$secret = openssl_pkey_derive(self::publicKeyFromPoint($peerPoint), $privateKey);
		if($secret === false){
			throw new DtlsException("ECDH key agreement failed");
		}

		return $secret;
	}
}
