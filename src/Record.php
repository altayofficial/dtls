<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * A single DTLS record.
 *
 * Records are self delimiting and several of them may share one datagram, which is why decoding
 * always works over a whole datagram and returns a list.
 */
final class Record{

	public const HEADER_LENGTH = 13;

	public function __construct(
		public readonly int $type,
		public readonly string $version,
		public readonly int $epoch,
		public readonly int $sequence,
		public readonly string $fragment
	){}

	public function encode() : string{
		return chr($this->type)
			. $this->version
			. pack("n", $this->epoch)
			. Protocol::uint48($this->sequence)
			. pack("n", strlen($this->fragment))
			. $this->fragment;
	}

	/**
	 * @return Record[]
	 */
	public static function decodeAll(string $datagram) : array{
		$records = [];
		$offset = 0;
		$total = strlen($datagram);

		while($offset + self::HEADER_LENGTH <= $total){
			$length = unpack("n", substr($datagram, $offset + 11, 2))[1];
			if($offset + self::HEADER_LENGTH + $length > $total){
				//a truncated trailing record is not recoverable, so stop rather than guess
				break;
			}

			$records[] = new Record(
				ord($datagram[$offset]),
				substr($datagram, $offset + 1, 2),
				unpack("n", substr($datagram, $offset + 3, 2))[1],
				Protocol::readUint48($datagram, $offset + 5),
				substr($datagram, $offset + self::HEADER_LENGTH, $length)
			);
			$offset += self::HEADER_LENGTH + $length;
		}

		return $records;
	}
}
