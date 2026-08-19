<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * Wire constants and the length prefixed vector helpers every message body is built from.
 *
 * TLS encodes variable length fields as a length prefix followed by the bytes, with the prefix
 * width varying per field. Getting a prefix wrong desyncs the whole handshake, so the encoders
 * live here rather than being written out by hand at each call site.
 */
final class Protocol{

	public const CONTENT_CHANGE_CIPHER_SPEC = 20;
	public const CONTENT_ALERT = 21;
	public const CONTENT_HANDSHAKE = 22;
	public const CONTENT_APPLICATION_DATA = 23;

	public const HANDSHAKE_CLIENT_HELLO = 1;
	public const HANDSHAKE_SERVER_HELLO = 2;
	public const HANDSHAKE_HELLO_VERIFY_REQUEST = 3;
	public const HANDSHAKE_CERTIFICATE = 11;
	public const HANDSHAKE_SERVER_KEY_EXCHANGE = 12;
	public const HANDSHAKE_CERTIFICATE_REQUEST = 13;
	public const HANDSHAKE_SERVER_HELLO_DONE = 14;
	public const HANDSHAKE_CERTIFICATE_VERIFY = 15;
	public const HANDSHAKE_CLIENT_KEY_EXCHANGE = 16;
	public const HANDSHAKE_FINISHED = 20;

	//DTLS versions are the ones complement of their TLS counterparts, so 1.2 is {254, 253}
	public const VERSION_1_0 = "\xfe\xff";
	public const VERSION_1_2 = "\xfe\xfd";

	public const CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xc02b;

	public const EXTENSION_SUPPORTED_GROUPS = 10;
	public const EXTENSION_EC_POINT_FORMATS = 11;
	public const EXTENSION_SIGNATURE_ALGORITHMS = 13;
	public const EXTENSION_USE_SRTP = 14;
	public const EXTENSION_EXTENDED_MASTER_SECRET = 23;
	public const EXTENSION_RENEGOTIATION_INFO = 0xff01;

	public const GROUP_SECP256R1 = 23;
	public const SIGNATURE_ECDSA_SHA256 = "\x04\x03";

	public const ALERT_LEVEL_WARNING = 1;
	public const ALERT_LEVEL_FATAL = 2;

	public const ALERT_CLOSE_NOTIFY = 0;
	public const ALERT_HANDSHAKE_FAILURE = 40;
	public const ALERT_BAD_CERTIFICATE = 42;
	public const ALERT_DECRYPT_ERROR = 51;
	public const ALERT_INTERNAL_ERROR = 80;

	private function __construct(){
		//static only
	}

	public static function uint24(int $value) : string{
		return substr(pack("N", $value), 1, 3);
	}

	public static function uint48(int $value) : string{
		return substr(pack("J", $value), 2, 6);
	}

	public static function readUint24(string $buffer, int $offset) : int{
		return unpack("N", "\x00" . substr($buffer, $offset, 3))[1];
	}

	public static function readUint48(string $buffer, int $offset) : int{
		return unpack("J", "\x00\x00" . substr($buffer, $offset, 6))[1];
	}

	public static function vector8(string $body) : string{
		return chr(strlen($body)) . $body;
	}

	public static function vector16(string $body) : string{
		return pack("n", strlen($body)) . $body;
	}

	public static function vector24(string $body) : string{
		return self::uint24(strlen($body)) . $body;
	}

	public static function extension(int $type, string $body) : string{
		return pack("n", $type) . self::vector16($body);
	}

	/**
	 * The 64 bit counter DTLS feeds into the AEAD nonce and additional data. Unlike TLS this is
	 * not the record sequence on its own - the epoch occupies the high 16 bits.
	 */
	public static function sequence(int $epoch, int $sequence) : string{
		return pack("n", $epoch) . self::uint48($sequence);
	}
}
