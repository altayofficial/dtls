<?php

declare(strict_types=1);

namespace altay\dtls;

use altay\dtls\Exception\AlertException;
use altay\dtls\Exception\DtlsException;
use altay\dtls\Exception\HandshakeException;
use Closure;
use OpenSSLAsymmetricKey;

/**
 * A DTLS 1.2 endpoint, client or server, implemented on ext-openssl alone.
 *
 * The connection owns no socket. Outbound datagrams go to the callback given at construction and
 * inbound ones are pushed in with handle(), which is what lets it sit on top of an ICE transport
 * as easily as a UDP socket.
 *
 * The negotiated suite is ECDHE-ECDSA-AES128-GCM-SHA256 with extended master secret, and both
 * sides present a certificate - WebRTC authenticates by comparing that certificate against the
 * fingerprint carried in the SDP rather than by walking a chain.
 */
final class Connection{

	public const STATE_NEW = 0;
	public const STATE_HANDSHAKING = 1;
	public const STATE_ESTABLISHED = 2;
	public const STATE_CLOSED = 3;
	public const STATE_FAILED = 4;

	private const MAX_HANDSHAKE_PAYLOAD = 1200;
	private const INITIAL_TIMEOUT = 1.0;
	private const MAX_TIMEOUT = 60.0;

	private int $state = self::STATE_NEW;

	private string $localRandom;
	private string $peerRandom = "";
	private string $cookie = "";
	private string $cookieSecret;

	private string $transcript = "";
	private int $sendSequence = 0;
	private int $messageSequence = 0;
	private int $epoch = 0;
	private int $writeSequence = 0;

	private FragmentReassembler $reassembler;
	private ReplayWindow $replay;

	private OpenSSLAsymmetricKey $ephemeralKey;
	private string $ephemeralPoint;
	private string $premaster = "";
	private ?KeySchedule $keys = null;
	private ?CipherState $cipher = null;

	private string $peerCertificateDer = "";
	private bool $extendedMasterSecret = false;
	private bool $peerRequestedCertificate = false;
	private bool $peerCipherChanged = false;

	/** @var string[] */
	private array $lastFlight = [];
	private float $retransmitAt = 0.0;
	private float $timeout = self::INITIAL_TIMEOUT;

	private ?Closure $onApplicationData = null;
	private ?Closure $onEstablished = null;

	private function __construct(
		private readonly bool $isClient,
		private readonly Certificate $certificate,
		private readonly Closure $send
	){
		$this->localRandom = pack("N", time()) . random_bytes(28);
		$this->cookieSecret = random_bytes(32);
		$this->reassembler = new FragmentReassembler();
		$this->replay = new ReplayWindow();

		$ephemeral = openssl_pkey_new(["ec" => ["curve_name" => "prime256v1"]]);
		if($ephemeral === false){
			throw new DtlsException("could not generate an ephemeral EC key");
		}

		$this->ephemeralKey = $ephemeral;
		$this->ephemeralPoint = Ec::pointOf($ephemeral);
	}

	public static function client(Certificate $certificate, callable $send) : self{
		return new self(true, $certificate, Closure::fromCallable($send));
	}

	public static function server(Certificate $certificate, callable $send) : self{
		return new self(false, $certificate, Closure::fromCallable($send));
	}

	public function onApplicationData(callable $handler) : void{
		$this->onApplicationData = Closure::fromCallable($handler);
	}

	public function onEstablished(callable $handler) : void{
		$this->onEstablished = Closure::fromCallable($handler);
	}

	public function getState() : int{
		return $this->state;
	}

	public function isEstablished() : bool{
		return $this->state === self::STATE_ESTABLISHED;
	}

	public function getPeerFingerprint() : ?string{
		return $this->peerCertificateDer === "" ? null : Certificate::fingerprintOf($this->peerCertificateDer);
	}

	public function getLocalFingerprint() : string{
		return $this->certificate->fingerprint();
	}

	/**
	 * Starts the handshake. Only the client has a first flight to send; a server simply waits.
	 */
	public function start() : void{
		if($this->state !== self::STATE_NEW){
			return;
		}
		$this->state = self::STATE_HANDSHAKING;

		if($this->isClient){
			$this->beginFlight();
			$this->writeHandshake(Protocol::HANDSHAKE_CLIENT_HELLO, $this->buildClientHello());
			$this->endFlight();
		}
	}

	public function send(string $data) : void{
		if($this->state !== self::STATE_ESTABLISHED){
			throw new DtlsException("connection is not established");
		}

		$this->emit($this->protect(Protocol::CONTENT_APPLICATION_DATA, $data));
	}

	public function close() : void{
		if($this->state === self::STATE_ESTABLISHED){
			$this->emit($this->protect(Protocol::CONTENT_ALERT, chr(Protocol::ALERT_LEVEL_WARNING) . chr(Protocol::ALERT_CLOSE_NOTIFY)));
		}
		$this->state = self::STATE_CLOSED;
	}

	/**
	 * Resends the last flight if the peer has gone quiet for too long, with the exponential
	 * backoff RFC 6347 asks for. Returns true if anything was retransmitted.
	 */
	public function handleTimeout(?float $now = null) : bool{
		$now ??= microtime(true);
		if($this->lastFlight === [] || $this->state !== self::STATE_HANDSHAKING || $now < $this->retransmitAt){
			return false;
		}

		foreach($this->lastFlight as $datagram){
			($this->send)($datagram);
		}

		$this->timeout = min($this->timeout * 2, self::MAX_TIMEOUT);
		$this->retransmitAt = $now + $this->timeout;

		return true;
	}

	/**
	 * Feeds one inbound datagram through the record layer.
	 */
	public function handle(string $datagram) : void{
		if($this->state === self::STATE_CLOSED || $this->state === self::STATE_FAILED){
			return;
		}

		try{
			foreach(Record::decodeAll($datagram) as $record){
				$this->handleRecord($record);
			}
			$this->drainHandshake();
		}catch(AlertException $e){
			$this->state = self::STATE_FAILED;
			throw $e;
		}catch(DtlsException $e){
			$this->state = self::STATE_FAILED;
			$this->sendAlert(Protocol::ALERT_LEVEL_FATAL, Protocol::ALERT_HANDSHAKE_FAILURE);
			throw $e;
		}
	}

	private function handleRecord(Record $record) : void{
		if($record->epoch === 1 && !$this->replay->accept($record->sequence)){
			return;
		}

		$fragment = $record->fragment;
		if($record->epoch === 1){
			if($this->cipher === null){
				//keys are not ready yet, so this record cannot be for us
				return;
			}
			$fragment = $this->cipher->open($record->type, $record->epoch, $record->sequence, $fragment);
		}

		switch($record->type){
			case Protocol::CONTENT_HANDSHAKE:
				foreach(HandshakeMessage::decodeAll($fragment) as $piece){
					$this->reassembler->push($piece);
				}
				break;

			case Protocol::CONTENT_CHANGE_CIPHER_SPEC:
				$this->peerCipherChanged = true;
				break;

			case Protocol::CONTENT_ALERT:
				$level = ord($fragment[0]);
				$description = ord($fragment[1]);
				if($description === Protocol::ALERT_CLOSE_NOTIFY){
					$this->state = self::STATE_CLOSED;

					return;
				}
				throw new AlertException($level, $description);

			case Protocol::CONTENT_APPLICATION_DATA:
				if($this->onApplicationData !== null){
					($this->onApplicationData)($fragment);
				}
				break;
		}
	}

	private function drainHandshake() : void{
		foreach($this->reassembler->drain() as $message){
			$this->handleHandshake($message);
		}
	}

	private function handleHandshake(HandshakeMessage $message) : void{
		//the cookie exchange sits outside the handshake proper and never enters the transcript
		if($message->type !== Protocol::HANDSHAKE_HELLO_VERIFY_REQUEST){
			$isRetriedHello = $message->type === Protocol::HANDSHAKE_CLIENT_HELLO && !$this->isClient;
			if($isRetriedHello){
				$this->transcript = "";
			}
			$this->transcript .= $message->transcriptBytes();
		}

		match($message->type){
			Protocol::HANDSHAKE_HELLO_VERIFY_REQUEST => $this->handleHelloVerifyRequest($message),
			Protocol::HANDSHAKE_CLIENT_HELLO => $this->handleClientHello($message),
			Protocol::HANDSHAKE_SERVER_HELLO => $this->handleServerHello($message),
			Protocol::HANDSHAKE_CERTIFICATE => $this->handleCertificate($message),
			Protocol::HANDSHAKE_SERVER_KEY_EXCHANGE => $this->handleServerKeyExchange($message),
			Protocol::HANDSHAKE_CERTIFICATE_REQUEST => $this->peerRequestedCertificate = true,
			Protocol::HANDSHAKE_SERVER_HELLO_DONE => $this->sendClientFlight(),
			Protocol::HANDSHAKE_CLIENT_KEY_EXCHANGE => $this->handleClientKeyExchange($message),
			Protocol::HANDSHAKE_CERTIFICATE_VERIFY => $this->handleCertificateVerify($message),
			Protocol::HANDSHAKE_FINISHED => $this->handleFinished($message),
			default => null
		};
	}

	private function handleHelloVerifyRequest(HandshakeMessage $message) : void{
		if(!$this->isClient){
			return;
		}

		$this->cookie = substr($message->body, 3, ord($message->body[2]));

		//the retried ClientHello starts the transcript over but keeps counting message_seq
		$this->transcript = "";
		$this->beginFlight();
		$this->writeHandshake(Protocol::HANDSHAKE_CLIENT_HELLO, $this->buildClientHello());
		$this->endFlight();
	}

	private function handleClientHello(HandshakeMessage $message) : void{
		if($this->isClient){
			return;
		}

		$hello = ClientHello::decode($message->body);
		$this->peerRandom = $hello->random;
		$this->extendedMasterSecret = $hello->extendedMasterSecret;

		$expected = $this->cookieFor($hello->random);
		if($hello->cookie === ""){
			//stateless retry: prove the peer can receive at the address it claims
			$this->transcript = "";
			$this->beginFlight();
			$this->writeHandshake(
				Protocol::HANDSHAKE_HELLO_VERIFY_REQUEST,
				Protocol::VERSION_1_2 . Protocol::vector8($expected)
			);
			$this->endFlight();

			return;
		}

		if(!hash_equals($expected, $hello->cookie)){
			throw new HandshakeException("client cookie did not verify");
		}

		if(!in_array(Protocol::CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256, $hello->cipherSuites, true)){
			throw new HandshakeException("peer does not offer ECDHE-ECDSA-AES128-GCM-SHA256");
		}

		$this->sendServerFlight();
	}

	private function handleServerHello(HandshakeMessage $message) : void{
		$hello = ServerHello::decode($message->body);
		$this->peerRandom = $hello->random;
		$this->extendedMasterSecret = $hello->extendedMasterSecret;

		if($hello->cipherSuite !== Protocol::CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256){
			throw new HandshakeException(sprintf("server chose unsupported cipher 0x%04x", $hello->cipherSuite));
		}
	}

	private function handleCertificate(HandshakeMessage $message) : void{
		//Certificate carries a chain; the peer's own certificate is the first entry. A peer with
		//no certificate to offer answers a CertificateRequest with an empty list rather than
		//omitting the message, so the body can legitimately be three zero bytes.
		if(strlen($message->body) < 6 || Protocol::readUint24($message->body, 0) === 0){
			return;
		}

		$length = Protocol::readUint24($message->body, 3);
		$this->peerCertificateDer = substr($message->body, 6, $length);
	}

	private function handleServerKeyExchange(HandshakeMessage $message) : void{
		$pointLength = ord($message->body[3]);
		$params = substr($message->body, 0, 4 + $pointLength);
		$point = substr($message->body, 4, $pointLength);
		$signature = substr($message->body, 4 + $pointLength);

		//the signature covers both randoms and the parameters, tying the ephemeral key to the
		//certificate and so to the fingerprint from signalling
		$signed = $this->localRandom . $this->peerRandom . $params;
		if(!$this->verifyWithPeerCertificate($signed, substr($signature, 4))){
			throw new HandshakeException("ServerKeyExchange signature did not verify");
		}

		$this->premaster = Ec::derive($point, $this->ephemeralKey);
	}

	private function handleClientKeyExchange(HandshakeMessage $message) : void{
		$point = substr($message->body, 1, ord($message->body[0]));
		$this->premaster = Ec::derive($point, $this->ephemeralKey);
		$this->installKeys();
	}

	private function handleCertificateVerify(HandshakeMessage $message) : void{
		//the transcript already contains this message, so strip it back off before verifying
		$signed = substr($this->transcript, 0, -strlen($message->transcriptBytes()));
		$signature = substr($message->body, 4);

		if(!$this->verifyWithPeerCertificate($signed, $signature)){
			throw new HandshakeException("CertificateVerify signature did not verify");
		}
	}

	private function handleFinished(HandshakeMessage $message) : void{
		if($this->keys === null){
			throw new HandshakeException("Finished arrived before the keys were established");
		}
		if(!$this->peerCipherChanged){
			//a Finished is only meaningful once the peer has switched to the negotiated keys
			throw new HandshakeException("Finished arrived before ChangeCipherSpec");
		}

		//the transcript already contains this Finished, so hash the state just before it
		$before = substr($this->transcript, 0, -strlen($message->transcriptBytes()));
		$label = $this->isClient ? "server finished" : "client finished";
		$expected = $this->keys->verifyData($label, hash("sha256", $before, true));

		if(!hash_equals($expected, $message->body)){
			throw new HandshakeException("Finished verify_data did not match");
		}

		if($this->isClient){
			$this->finish();
		}else{
			//the server answers a verified client Finished with its own
			$this->beginFlight();
			$this->changeCipherSpec();
			$this->writeFinished("server finished");
			$this->endFlight();
			$this->finish();
		}
	}

	private function sendClientFlight() : void{
		if(!$this->isClient){
			return;
		}

		$this->beginFlight();

		if($this->peerRequestedCertificate){
			$this->writeHandshake(
				Protocol::HANDSHAKE_CERTIFICATE,
				Protocol::vector24(Protocol::vector24($this->certificate->der()))
			);
		}

		$this->writeHandshake(Protocol::HANDSHAKE_CLIENT_KEY_EXCHANGE, Protocol::vector8($this->ephemeralPoint));

		//the extended master secret is bound to the transcript up to and including
		//ClientKeyExchange, so the keys have to be derived here rather than after
		//CertificateVerify - the peer derives at exactly this point too
		$this->installKeys();

		if($this->peerRequestedCertificate){
			//signed over every handshake message so far, proving we hold the certificate's key
			openssl_sign($this->transcript, $signature, $this->certificate->privateKey(), OPENSSL_ALGO_SHA256);
			$this->writeHandshake(
				Protocol::HANDSHAKE_CERTIFICATE_VERIFY,
				Protocol::SIGNATURE_ECDSA_SHA256 . Protocol::vector16($signature)
			);
		}

		$this->changeCipherSpec();
		$this->writeFinished("client finished");
		$this->endFlight();
	}

	private function sendServerFlight() : void{
		$this->beginFlight();

		$this->writeHandshake(Protocol::HANDSHAKE_SERVER_HELLO, $this->buildServerHello());
		$this->writeHandshake(
			Protocol::HANDSHAKE_CERTIFICATE,
			Protocol::vector24(Protocol::vector24($this->certificate->der()))
		);

		$params = "\x03" . pack("n", Protocol::GROUP_SECP256R1) . Protocol::vector8($this->ephemeralPoint);
		openssl_sign($this->peerRandom . $this->localRandom . $params, $signature, $this->certificate->privateKey(), OPENSSL_ALGO_SHA256);
		$this->writeHandshake(
			Protocol::HANDSHAKE_SERVER_KEY_EXCHANGE,
			$params . Protocol::SIGNATURE_ECDSA_SHA256 . Protocol::vector16($signature)
		);

		//WebRTC is mutually authenticated - both ends present a certificate to match against
		//the fingerprint that came over signalling
		$this->writeHandshake(
			Protocol::HANDSHAKE_CERTIFICATE_REQUEST,
			Protocol::vector8("\x40") . Protocol::vector16(Protocol::SIGNATURE_ECDSA_SHA256) . Protocol::vector16("")
		);

		$this->writeHandshake(Protocol::HANDSHAKE_SERVER_HELLO_DONE, "");
		$this->endFlight();
	}

	private function buildClientHello() : string{
		$extensions = Protocol::extension(Protocol::EXTENSION_SUPPORTED_GROUPS, Protocol::vector16(pack("n", Protocol::GROUP_SECP256R1)))
			. Protocol::extension(Protocol::EXTENSION_EC_POINT_FORMATS, Protocol::vector8("\x00"))
			. Protocol::extension(Protocol::EXTENSION_SIGNATURE_ALGORITHMS, Protocol::vector16(Protocol::SIGNATURE_ECDSA_SHA256))
			. Protocol::extension(Protocol::EXTENSION_EXTENDED_MASTER_SECRET, "")
			. Protocol::extension(Protocol::EXTENSION_RENEGOTIATION_INFO, Protocol::vector8(""));

		return Protocol::VERSION_1_2
			. $this->localRandom
			. Protocol::vector8("")
			. Protocol::vector8($this->cookie)
			. Protocol::vector16(pack("n", Protocol::CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256))
			. Protocol::vector8("\x00")
			. Protocol::vector16($extensions);
	}

	private function buildServerHello() : string{
		$extensions = Protocol::extension(Protocol::EXTENSION_EC_POINT_FORMATS, Protocol::vector8("\x00"))
			. Protocol::extension(Protocol::EXTENSION_RENEGOTIATION_INFO, Protocol::vector8(""));

		if($this->extendedMasterSecret){
			$extensions .= Protocol::extension(Protocol::EXTENSION_EXTENDED_MASTER_SECRET, "");
		}

		return Protocol::VERSION_1_2
			. $this->localRandom
			. Protocol::vector8("")
			. pack("n", Protocol::CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256)
			. "\x00"
			. Protocol::vector16($extensions);
	}

	private function installKeys() : void{
		if($this->keys !== null){
			return;
		}
		if($this->premaster === ""){
			throw new HandshakeException("no shared secret to derive keys from");
		}

		$clientRandom = $this->isClient ? $this->localRandom : $this->peerRandom;
		$serverRandom = $this->isClient ? $this->peerRandom : $this->localRandom;

		//with extended master secret the binding is to the transcript through ClientKeyExchange,
		//which is exactly what the transcript holds at this point
		$this->keys = KeySchedule::derive(
			$this->premaster,
			$clientRandom,
			$serverRandom,
			$this->extendedMasterSecret,
			hash("sha256", $this->transcript, true)
		);

		$this->cipher = $this->isClient
			? new CipherState($this->keys->clientWriteKey, $this->keys->clientWriteSalt, $this->keys->serverWriteKey, $this->keys->serverWriteSalt)
			: new CipherState($this->keys->serverWriteKey, $this->keys->serverWriteSalt, $this->keys->clientWriteKey, $this->keys->clientWriteSalt);
	}

	private function writeFinished(string $label) : void{
		$verify = $this->keys->verifyData($label, hash("sha256", $this->transcript, true));
		$this->writeHandshake(Protocol::HANDSHAKE_FINISHED, $verify);
	}

	private function changeCipherSpec() : void{
		$this->emitFlight(new Record(Protocol::CONTENT_CHANGE_CIPHER_SPEC, Protocol::VERSION_1_2, $this->epoch, $this->sendSequence++, "\x01"));
		$this->epoch = 1;
		$this->writeSequence = 0;
	}

	/**
	 * Appends a handshake message to the transcript and puts it on the wire, fragmenting it if
	 * it would not fit in a datagram.
	 */
	private function writeHandshake(int $type, string $body) : void{
		$message = new HandshakeMessage($type, $this->messageSequence++, $body);

		//HelloVerifyRequest is outside the handshake proper, so it stays out of the transcript
		if($type !== Protocol::HANDSHAKE_HELLO_VERIFY_REQUEST){
			$this->transcript .= $message->transcriptBytes();
		}

		foreach($message->fragment(self::MAX_HANDSHAKE_PAYLOAD) as $fragment){
			$encoded = $fragment->encode();
			if($this->epoch === 1){
				$this->emitFlight($this->protectRecord(Protocol::CONTENT_HANDSHAKE, $encoded));
			}else{
				$version = $type === Protocol::HANDSHAKE_CLIENT_HELLO && $this->cookie === ""
					? Protocol::VERSION_1_0
					: Protocol::VERSION_1_2;
				$this->emitFlight(new Record(Protocol::CONTENT_HANDSHAKE, $version, $this->epoch, $this->sendSequence++, $encoded));
			}
		}
	}

	private function protect(int $type, string $plaintext) : Record{
		return $this->protectRecord($type, $plaintext);
	}

	private function protectRecord(int $type, string $plaintext) : Record{
		if($this->cipher === null){
			throw new DtlsException("cannot protect a record before the keys exist");
		}

		$sequence = $this->writeSequence++;

		return new Record(
			$type,
			Protocol::VERSION_1_2,
			1,
			$sequence,
			$this->cipher->seal($type, 1, $sequence, $plaintext)
		);
	}

	private function sendAlert(int $level, int $description) : void{
		$body = chr($level) . chr($description);

		if($this->cipher !== null && $this->epoch === 1){
			$this->emit($this->protect(Protocol::CONTENT_ALERT, $body));
		}else{
			$this->emit(new Record(Protocol::CONTENT_ALERT, Protocol::VERSION_1_2, $this->epoch, $this->sendSequence++, $body));
		}
	}

	private function beginFlight() : void{
		$this->lastFlight = [];
	}

	private function endFlight() : void{
		$this->timeout = self::INITIAL_TIMEOUT;
		$this->retransmitAt = microtime(true) + $this->timeout;
	}

	private function emitFlight(Record $record) : void{
		$datagram = $record->encode();
		$this->lastFlight[] = $datagram;
		($this->send)($datagram);
	}

	private function emit(Record $record) : void{
		($this->send)($record->encode());
	}

	private function finish() : void{
		$this->state = self::STATE_ESTABLISHED;
		$this->lastFlight = [];

		if($this->onEstablished !== null){
			($this->onEstablished)();
		}
	}

	private function verifyWithPeerCertificate(string $data, string $signature) : bool{
		if($this->peerCertificateDer === ""){
			return false;
		}

		$public = openssl_pkey_get_public(Certificate::derToPem($this->peerCertificateDer));
		if($public === false){
			return false;
		}

		return openssl_verify($data, $signature, $public, OPENSSL_ALGO_SHA256) === 1;
	}

	private function cookieFor(string $clientRandom) : string{
		return hash_hmac("sha256", $clientRandom, $this->cookieSecret, true);
	}
}
