<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * One handshake message, possibly a fragment of a larger one.
 *
 * DTLS adds message_seq, fragment_offset and fragment_length to the TLS handshake header so a
 * message can be split across datagrams and reordered on the way. The transcript that both sides
 * hash is always the unfragmented form, which is why that encoding is kept separate.
 */
final class HandshakeMessage{

	public const HEADER_LENGTH = 12;

	public function __construct(
		public readonly int $type,
		public readonly int $messageSequence,
		public readonly string $body,
		public readonly int $fragmentOffset = 0,
		public readonly ?int $totalLength = null
	){}

	public function length() : int{
		return $this->totalLength ?? strlen($this->body);
	}

	public function encode() : string{
		return chr($this->type)
			. Protocol::uint24($this->length())
			. pack("n", $this->messageSequence)
			. Protocol::uint24($this->fragmentOffset)
			. Protocol::uint24(strlen($this->body))
			. $this->body;
	}

	/**
	 * The bytes that go into the handshake transcript - always unfragmented, regardless of how
	 * the message actually travelled.
	 */
	public function transcriptBytes() : string{
		$length = $this->length();

		return chr($this->type)
			. Protocol::uint24($length)
			. pack("n", $this->messageSequence)
			. Protocol::uint24(0)
			. Protocol::uint24($length)
			. $this->body;
	}

	/**
	 * Splits a message so each piece fits inside the given payload budget.
	 *
	 * @return HandshakeMessage[]
	 */
	public function fragment(int $maxPayload) : array{
		$body = $this->body;
		$total = strlen($body);
		if($total <= $maxPayload){
			return [$this];
		}

		$fragments = [];
		for($offset = 0; $offset < $total; $offset += $maxPayload){
			$fragments[] = new HandshakeMessage(
				$this->type,
				$this->messageSequence,
				substr($body, $offset, $maxPayload),
				$offset,
				$total
			);
		}

		return $fragments;
	}

	/**
	 * @return HandshakeMessage[]
	 */
	public static function decodeAll(string $buffer) : array{
		$messages = [];
		$offset = 0;
		$total = strlen($buffer);

		while($offset + self::HEADER_LENGTH <= $total){
			//header is type(1) length(3) message_seq(2) fragment_offset(3) fragment_length(3)
			$length = Protocol::readUint24($buffer, $offset + 1);
			$fragmentLength = Protocol::readUint24($buffer, $offset + 9);
			if($offset + self::HEADER_LENGTH + $fragmentLength > $total){
				break;
			}

			$messages[] = new HandshakeMessage(
				ord($buffer[$offset]),
				unpack("n", substr($buffer, $offset + 4, 2))[1],
				substr($buffer, $offset + self::HEADER_LENGTH, $fragmentLength),
				Protocol::readUint24($buffer, $offset + 6),
				$length
			);
			$offset += self::HEADER_LENGTH + $fragmentLength;
		}

		return $messages;
	}
}
