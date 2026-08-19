<?php

declare(strict_types=1);

namespace altay\dtls;

/**
 * Sliding window that rejects replayed or far too old record sequence numbers.
 *
 * DTLS runs over an unreliable transport, so duplicates are expected and dropping them is a
 * correctness matter as much as a security one - an AEAD nonce must never be accepted twice.
 */
final class ReplayWindow{

	private const WINDOW = 64;

	private int $highest = -1;
	private int $bitmap = 0;

	public function accept(int $sequence) : bool{
		if($sequence > $this->highest){
			$shift = $this->highest < 0 ? 0 : $sequence - $this->highest;
			$this->bitmap = $shift >= self::WINDOW ? 0 : ($this->bitmap << $shift) & ((1 << self::WINDOW) - 1);
			$this->bitmap |= 1;
			$this->highest = $sequence;

			return true;
		}

		$age = $this->highest - $sequence;
		if($age >= self::WINDOW){
			//too old to prove it is not a replay
			return false;
		}

		$mask = 1 << $age;
		if(($this->bitmap & $mask) !== 0){
			return false;
		}
		$this->bitmap |= $mask;

		return true;
	}
}
