<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * Rebuilds whole handshake messages out of the fragments that arrive.
 *
 * Fragments carrying the same message_seq belong to one message and are placed by offset, so
 * retransmissions that overlap differently to the original are harmless. A message is released
 * exactly once, in message_seq order, and only after every byte of it has been seen.
 */
final class FragmentReassembler{

	/** @var array<int, array{type: int, length: int, body: string, seen: array<int, int>}> */
	private array $partial = [];

	/** @var array<int, true> */
	private array $released = [];

	private int $nextSequence = 0;

	public function __construct(int $firstSequence = 0){
		$this->nextSequence = $firstSequence;
	}

	/**
	 * Marks every message up to (but excluding) the given sequence as already handled.
	 *
	 * Used after a HelloVerifyRequest exchange, where the cookie round trip is not part of the
	 * handshake proper and must not be replayed into the transcript.
	 */
	public function skipTo(int $sequence) : void{
		for($i = $this->nextSequence; $i < $sequence; $i++){
			$this->released[$i] = true;
		}
		$this->nextSequence = $sequence;
	}

	public function push(HandshakeMessage $fragment) : void{
		$sequence = $fragment->messageSequence;
		if(isset($this->released[$sequence])){
			//a retransmission of something already handed on
			return;
		}

		$length = $fragment->totalLength ?? strlen($fragment->body);
		if(!isset($this->partial[$sequence])){
			$this->partial[$sequence] = [
				"type" => $fragment->type,
				"length" => $length,
				"body" => str_repeat("\x00", $length),
				"seen" => []
			];
		}

		$slot = &$this->partial[$sequence];
		$slot["body"] = substr_replace($slot["body"], $fragment->body, $fragment->fragmentOffset, strlen($fragment->body));
		$slot["seen"][$fragment->fragmentOffset] = max(
			$slot["seen"][$fragment->fragmentOffset] ?? 0,
			strlen($fragment->body)
		);
		unset($slot);
	}

	/**
	 * Returns the messages that are now complete, in order, and never returns one twice.
	 *
	 * @return HandshakeMessage[]
	 */
	public function drain() : array{
		$ready = [];

		while(isset($this->partial[$this->nextSequence])){
			$slot = $this->partial[$this->nextSequence];
			if(!$this->isComplete($slot)){
				break;
			}

			$ready[] = new HandshakeMessage($slot["type"], $this->nextSequence, $slot["body"]);
			$this->released[$this->nextSequence] = true;
			unset($this->partial[$this->nextSequence]);
			$this->nextSequence++;
		}

		return $ready;
	}

	/**
	 * @param array{type: int, length: int, body: string, seen: array<int, int>} $slot
	 */
	private function isComplete(array $slot) : bool{
		$offsets = $slot["seen"];
		ksort($offsets);

		$covered = 0;
		foreach($offsets as $offset => $length){
			if($offset > $covered){
				//a hole - some fragment in the middle has not arrived yet
				return false;
			}
			$covered = max($covered, $offset + $length);
		}

		return $covered >= $slot["length"];
	}
}
