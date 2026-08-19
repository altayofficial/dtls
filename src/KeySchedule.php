<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * TLS 1.2 key derivation for the AEAD suites, driven entirely by ext-openssl and hash_hmac.
 *
 * The suite in use is ECDHE-ECDSA-AES128-GCM-SHA256, so there are no MAC keys: the key block is
 * two 16 byte keys plus two 4 byte implicit nonce salts.
 */
final class KeySchedule{

	private const KEY_LENGTH = 16;
	private const SALT_LENGTH = 4;

	public function __construct(
		public readonly string $masterSecret,
		public readonly string $clientWriteKey,
		public readonly string $serverWriteKey,
		public readonly string $clientWriteSalt,
		public readonly string $serverWriteSalt
	){}

	/**
	 * @param string $premaster the raw ECDH shared secret
	 * @param string $sessionHash transcript hash through ClientKeyExchange, for extended master secret
	 */
	public static function derive(
		string $premaster,
		string $clientRandom,
		string $serverRandom,
		bool $extendedMasterSecret,
		string $sessionHash
	) : self{
		//RFC 7627 binds the master secret to the whole handshake rather than just the two
		//randoms, which is what stops the triple handshake family of attacks
		$master = $extendedMasterSecret
			? self::prf($premaster, "extended master secret", $sessionHash, 48)
			: self::prf($premaster, "master secret", $clientRandom . $serverRandom, 48);

		//note the reversed random order here - the key block seed is server||client
		$block = self::prf($master, "key expansion", $serverRandom . $clientRandom, 2 * (self::KEY_LENGTH + self::SALT_LENGTH));

		return new self(
			$master,
			substr($block, 0, self::KEY_LENGTH),
			substr($block, self::KEY_LENGTH, self::KEY_LENGTH),
			substr($block, 2 * self::KEY_LENGTH, self::SALT_LENGTH),
			substr($block, 2 * self::KEY_LENGTH + self::SALT_LENGTH, self::SALT_LENGTH)
		);
	}

	public function verifyData(string $label, string $transcriptHash) : string{
		return self::prf($this->masterSecret, $label, $transcriptHash, 12);
	}

	/**
	 * The TLS 1.2 pseudo random function, P_SHA256.
	 */
	public static function prf(string $secret, string $label, string $seed, int $length) : string{
		$seed = $label . $seed;
		$output = "";
		$a = $seed;

		while(strlen($output) < $length){
			$a = hash_hmac("sha256", $a, $secret, true);
			$output .= hash_hmac("sha256", $a . $seed, $secret, true);
		}

		return substr($output, 0, $length);
	}
}
