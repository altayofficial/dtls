<?php

declare(strict_types=1);

namespace altay\dtls;

use altay\dtls\Exception\DtlsException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

/**
 * A self signed ECDSA P-256 identity, plus the SHA-256 fingerprint that goes in the SDP.
 *
 * WebRTC does not use a PKI: the offer and answer carry an a=fingerprint line, and a peer is
 * trusted precisely when the certificate it presents hashes to the value that arrived over
 * signalling. That is why nothing here builds or validates a chain.
 */
final class Certificate{

	private function __construct(
		private readonly OpenSSLAsymmetricKey $privateKey,
		private readonly string $der
	){}

	public static function generate(string $commonName = "WebRTC", int $days = 30) : self{
		$key = openssl_pkey_new([
			"private_key_type" => OPENSSL_KEYTYPE_EC,
			"curve_name" => "prime256v1"
		]);
		if($key === false){
			throw new DtlsException("could not generate an EC key");
		}

		$csr = openssl_csr_new(["commonName" => $commonName], $key, ["digest_alg" => "sha256"]);
		if($csr === false){
			throw new DtlsException("could not build a certificate request");
		}

		$certificate = openssl_csr_sign($csr, null, $key, $days, ["digest_alg" => "sha256"]);
		if($certificate === false){
			throw new DtlsException("could not self sign the certificate");
		}

		return new self($key, self::toDer($certificate));
	}

	public static function fromPem(string $certificatePem, string $privateKeyPem) : self{
		$certificate = openssl_x509_read($certificatePem);
		if($certificate === false){
			throw new DtlsException("unreadable certificate");
		}

		$key = openssl_pkey_get_private($privateKeyPem);
		if($key === false){
			throw new DtlsException("unreadable private key");
		}

		return new self($key, self::toDer($certificate));
	}

	public function der() : string{
		return $this->der;
	}

	public function privateKey() : OpenSSLAsymmetricKey{
		return $this->privateKey;
	}

	/**
	 * Colon separated uppercase SHA-256, the form used on an SDP a=fingerprint line.
	 */
	public function fingerprint() : string{
		return self::fingerprintOf($this->der);
	}

	public static function fingerprintOf(string $der) : string{
		return strtoupper(implode(":", str_split(hash("sha256", $der), 2)));
	}

	public static function derToPem(string $der) : string{
		return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
	}

	private static function toDer(OpenSSLCertificate $certificate) : string{
		if(!openssl_x509_export($certificate, $pem)){
			throw new DtlsException("could not export the certificate");
		}

		$body = preg_replace("/-----[A-Z ]+-----|\s+/", "", $pem);
		$der = base64_decode($body, true);
		if($der === false){
			throw new DtlsException("could not decode the certificate");
		}

		return $der;
	}
}
