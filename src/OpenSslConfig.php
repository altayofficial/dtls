<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * Several openssl_*() functions load openssl.cnf before doing anything, and the static PHP builds
 * used by most servers point at a path that doesn't exist on the host. That makes CSR creation and
 * key export fail with "BIO routines::no such file" on machines that are otherwise perfectly fine,
 * so we ship a config of our own and hand it to those calls.
 */
final class OpenSslConfig{

	private function __construct(){}

	public static function path() : string{
		return __DIR__ . "/../resources/openssl.cnf";
	}

	/**
	 * @return array<string, string>
	 */
	public static function options() : array{
		$path = self::path();
		return is_file($path) ? ["config" => $path] : [];
	}
}
