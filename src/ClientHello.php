<?php

declare(strict_types=1);

namespace altay\dtls;

use altay\dtls\Exception\HandshakeException;

/**
 * The parts of a ClientHello a server needs to answer it.
 */
final class ClientHello{

	/**
	 * @param int[] $cipherSuites
	 */
	public function __construct(
		public readonly string $random,
		public readonly string $cookie,
		public readonly array $cipherSuites,
		public readonly bool $extendedMasterSecret
	){}

	public static function decode(string $body) : self{
		$offset = 2;

		$random = substr($body, $offset, 32);
		$offset += 32;

		$offset += 1 + ord($body[$offset]);          //session id
		$cookieLength = ord($body[$offset]);
		$cookie = substr($body, $offset + 1, $cookieLength);
		$offset += 1 + $cookieLength;

		$suiteBytes = unpack("n", substr($body, $offset, 2))[1];
		$offset += 2;
		if($suiteBytes % 2 !== 0){
			throw new HandshakeException("malformed cipher suite list");
		}
		$suites = array_values(unpack("n*", substr($body, $offset, $suiteBytes)));
		$offset += $suiteBytes;

		$offset += 1 + ord($body[$offset]);          //compression methods

		$extensions = strlen($body) > $offset + 2
			? Extensions::decode(substr($body, $offset + 2, unpack("n", substr($body, $offset, 2))[1]))
			: [];

		return new self($random, $cookie, $suites, isset($extensions[Protocol::EXTENSION_EXTENDED_MASTER_SECRET]));
	}
}
