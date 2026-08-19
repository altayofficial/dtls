<?php

declare(strict_types=1);

namespace altay\dtls;

use altay\dtls\Exception\DtlsException;

/**
 * AES-128-GCM record protection.
 *
 * The nonce is the 4 byte implicit salt from the key block followed by the 8 byte explicit part
 * carried in the record, which for DTLS is epoch||sequence_number. The additional data covers the
 * same counter plus the record header fields, binding each record to its position in the stream.
 */
final class CipherState{

	private const TAG_LENGTH = 16;
	private const EXPLICIT_NONCE_LENGTH = 8;

	public function __construct(
		private readonly string $writeKey,
		private readonly string $writeSalt,
		private readonly string $readKey,
		private readonly string $readSalt
	){}

	public function seal(int $type, int $epoch, int $sequence, string $plaintext) : string{
		$explicit = Protocol::sequence($epoch, $sequence);
		$additional = $explicit . chr($type) . Protocol::VERSION_1_2 . pack("n", strlen($plaintext));

		$sealed = openssl_encrypt(
			$plaintext,
			"aes-128-gcm",
			$this->writeKey,
			OPENSSL_RAW_DATA,
			$this->writeSalt . $explicit,
			$tag,
			$additional,
			self::TAG_LENGTH
		);

		if($sealed === false){
			throw new DtlsException("failed to seal record");
		}

		return $explicit . $sealed . $tag;
	}

	public function open(int $type, int $epoch, int $sequence, string $fragment) : string{
		if(strlen($fragment) < self::EXPLICIT_NONCE_LENGTH + self::TAG_LENGTH){
			throw new DtlsException("record too short to be authenticated");
		}

		$explicit = substr($fragment, 0, self::EXPLICIT_NONCE_LENGTH);
		$body = substr($fragment, self::EXPLICIT_NONCE_LENGTH, -self::TAG_LENGTH);
		$tag = substr($fragment, -self::TAG_LENGTH);
		$additional = Protocol::sequence($epoch, $sequence) . chr($type) . Protocol::VERSION_1_2 . pack("n", strlen($body));

		$plaintext = openssl_decrypt(
			$body,
			"aes-128-gcm",
			$this->readKey,
			OPENSSL_RAW_DATA,
			$this->readSalt . $explicit,
			$tag,
			$additional
		);

		if($plaintext === false){
			throw new DtlsException("record failed authentication");
		}

		return $plaintext;
	}
}
