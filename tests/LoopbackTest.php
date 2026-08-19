<?php

declare(strict_types=1);

namespace altay\dtls\tests;

use altay\dtls\Certificate;
use altay\dtls\Connection;
use PHPUnit\Framework\TestCase;

/**
 * Drives a client and a server against each other in memory, so the whole handshake runs without
 * a socket. Datagrams are passed by hand, which also makes it easy to lose and duplicate them.
 */
final class LoopbackTest extends TestCase{

	/** @var string[] */
	private array $toServer = [];

	/** @var string[] */
	private array $toClient = [];

	private Connection $client;
	private Connection $server;

	protected function setUp() : void{
		$this->toServer = [];
		$this->toClient = [];

		$this->client = Connection::client(Certificate::generate(), function(string $datagram) : void{
			$this->toServer[] = $datagram;
		});
		$this->server = Connection::server(Certificate::generate(), function(string $datagram) : void{
			$this->toClient[] = $datagram;
		});
	}

	public function testHandshakeCompletesBothWays() : void{
		$this->client->start();
		$this->pump();

		self::assertTrue($this->client->isEstablished(), "client did not establish");
		self::assertTrue($this->server->isEstablished(), "server did not establish");
	}

	public function testEachSideSeesTheOthersFingerprint() : void{
		$this->client->start();
		$this->pump();

		self::assertSame($this->server->getLocalFingerprint(), $this->client->getPeerFingerprint());
		self::assertSame($this->client->getLocalFingerprint(), $this->server->getPeerFingerprint());
	}

	public function testApplicationDataFlowsInBothDirections() : void{
		$fromServer = [];
		$fromClient = [];

		$this->client->onApplicationData(function(string $data) use (&$fromServer) : void{
			$fromServer[] = $data;
		});
		$this->server->onApplicationData(function(string $data) use (&$fromClient) : void{
			$fromClient[] = $data;
		});

		$this->client->start();
		$this->pump();

		$this->client->send("ping");
		$this->pump();
		$this->server->send("pong");
		$this->pump();

		self::assertSame(["ping"], $fromClient);
		self::assertSame(["pong"], $fromServer);
	}

	public function testBinaryPayloadSurvivesIntact() : void{
		$payload = random_bytes(1024);
		$received = null;

		$this->server->onApplicationData(function(string $data) use (&$received) : void{
			$received = $data;
		});

		$this->client->start();
		$this->pump();
		$this->client->send($payload);
		$this->pump();

		self::assertSame(bin2hex($payload), bin2hex((string) $received));
	}

	public function testDuplicatedDatagramsAreIgnored() : void{
		$received = [];
		$this->server->onApplicationData(function(string $data) use (&$received) : void{
			$received[] = $data;
		});

		$this->client->start();
		$this->pump();

		//replay every datagram the client sends; the anti replay window must swallow the copies
		$this->client->send("once");
		$copies = $this->toServer;
		foreach($copies as $datagram){
			$this->toServer[] = $datagram;
		}
		$this->pump();

		self::assertSame(["once"], $received);
	}

	public function testHandshakeSurvivesALostFlight() : void{
		$this->client->start();

		//drop the client's opening flight entirely, then let the retransmit timer recover it
		$this->toServer = [];
		self::assertTrue($this->client->handleTimeout(microtime(true) + 5.0), "client did not retransmit");

		$this->pump();

		self::assertTrue($this->client->isEstablished(), "client did not establish after loss");
		self::assertTrue($this->server->isEstablished(), "server did not establish after loss");
	}

	public function testCloseNotifyShutsTheConnectionDown() : void{
		$this->client->start();
		$this->pump();

		$this->client->close();
		$this->pump();

		self::assertSame(Connection::STATE_CLOSED, $this->client->getState());
		self::assertSame(Connection::STATE_CLOSED, $this->server->getState());
	}

	/**
	 * Shuttles datagrams between the two ends until neither has anything left to say.
	 */
	private function pump() : void{
		for($i = 0; $i < 64; $i++){
			if($this->toServer === [] && $this->toClient === []){
				return;
			}

			$inbound = $this->toServer;
			$this->toServer = [];
			foreach($inbound as $datagram){
				$this->server->handle($datagram);
			}

			$inbound = $this->toClient;
			$this->toClient = [];
			foreach($inbound as $datagram){
				$this->client->handle($datagram);
			}
		}

		self::fail("datagrams never settled");
	}
}
