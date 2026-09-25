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

	private static ?string $path = null;

	private function __construct(){}

	public static function path() : string{
		return self::$path ??= self::resolvePath();
	}

	/**
	 * @return array<string, string>
	 */
	public static function options() : array{
		$path = self::path();
		return is_file($path) ? ["config" => $path] : [];
	}

	private static function resolvePath() : string{
		$path = __DIR__ . "/../resources/openssl.cnf";
		if(!str_starts_with($path, "phar://")){
			return $path;
		}

		//OpenSSL opens the file with plain C I/O, so a path inside a phar is as good as missing
		$contents = @file_get_contents($path);
		if($contents === false){
			return $path;
		}
		$extracted = sys_get_temp_dir() . "/altay-dtls-openssl-" . hash("crc32b", $contents) . ".cnf";
		if(!is_file($extracted) && @file_put_contents($extracted, $contents) === false){
			return $path;
		}
		return $extracted;
	}
}
