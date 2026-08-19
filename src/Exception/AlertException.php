<?php

declare(strict_types=1);

namespace altay\dtls\Exception;

use altay\dtls\Protocol;

/**
 * A fatal alert received from the peer, or one this side is about to send.
 */
class AlertException extends DtlsException{

	public function __construct(private readonly int $level, private readonly int $description){
		parent::__construct(sprintf("DTLS alert %d (level %d)", $description, $level));
	}

	public function getLevel() : int{
		return $this->level;
	}

	public function getDescription() : int{
		return $this->description;
	}

	public function isFatal() : bool{
		return $this->level === Protocol::ALERT_LEVEL_FATAL;
	}
}
