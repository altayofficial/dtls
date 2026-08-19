<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * The parts of a ServerHello a client needs to continue.
 */
final class ServerHello{

	public function __construct(
		public readonly string $random,
		public readonly int $cipherSuite,
		public readonly bool $extendedMasterSecret
	){}

	public static function decode(string $body) : self{
		$offset = 2;

		$random = substr($body, $offset, 32);
		$offset += 32;

		$offset += 1 + ord($body[$offset]);          //session id

		$suite = unpack("n", substr($body, $offset, 2))[1];
		$offset += 3;                                //cipher suite plus compression method

		$extensions = strlen($body) > $offset + 2
			? Extensions::decode(substr($body, $offset + 2, unpack("n", substr($body, $offset, 2))[1]))
			: [];

		return new self($random, $suite, isset($extensions[Protocol::EXTENSION_EXTENDED_MASTER_SECRET]));
	}
}
