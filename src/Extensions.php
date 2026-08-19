<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * Hello extension block parsing.
 */
final class Extensions{

	private function __construct(){
		//static only
	}

	/**
	 * @return array<int, string> extension type to body
	 */
	public static function decode(string $block) : array{
		$extensions = [];
		$offset = 0;
		$total = strlen($block);

		while($offset + 4 <= $total){
			$type = unpack("n", substr($block, $offset, 2))[1];
			$length = unpack("n", substr($block, $offset + 2, 2))[1];
			if($offset + 4 + $length > $total){
				break;
			}

			$extensions[$type] = substr($block, $offset + 4, $length);
			$offset += 4 + $length;
		}

		return $extensions;
	}
}
