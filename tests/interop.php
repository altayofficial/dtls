<?php

declare(strict_types=1);

/**
 * Interoperability check against the OpenSSL command line tools.
 *
 * The loopback tests prove the implementation agrees with itself, which a consistent bug would
 * also satisfy. This drives a real OpenSSL peer instead, in both roles.
 *
 * Usage: php tests/interop.php client|server <port>
 */

require __DIR__ . "/../vendor/autoload.php";

use altay\dtls\Certificate;
use altay\dtls\Connection;

$role = $argv[1] ?? "client";
$port = (int) ($argv[2] ?? 4444);

if($role === "client"){
	//we dial an openssl s_server
	$socket = stream_socket_client("udp://127.0.0.1:$port", $errno, $errstr);
	if($socket === false){
		fwrite(STDERR, "connect failed: $errstr\n");
		exit(1);
	}
	stream_set_timeout($socket, 5);

	$connection = Connection::client(Certificate::generate(), function(string $datagram) use ($socket) : void{
		fwrite($socket, $datagram);
	});
}else{
	//an openssl s_client dials us
	$socket = stream_socket_server("udp://127.0.0.1:$port", $errno, $errstr, STREAM_SERVER_BIND);
	if($socket === false){
		fwrite(STDERR, "bind failed: $errstr\n");
		exit(1);
	}
	stream_set_timeout($socket, 15);

	$peer = null;
	$connection = Connection::server(Certificate::generate(), function(string $datagram) use ($socket, &$peer) : void{
		if($peer !== null){
			stream_socket_sendto($socket, $datagram, 0, $peer);
		}
	});
}

$established = false;
$connection->onEstablished(function() use (&$established) : void{
	$established = true;
});

$received = [];
$connection->onApplicationData(function(string $data) use (&$received) : void{
	$received[] = $data;
	echo "  app data in: " . trim($data) . "\n";
});

$connection->start();

$deadline = microtime(true) + 15.0;
$sent = false;

while(microtime(true) < $deadline){
	if($role === "client"){
		$datagram = @fread($socket, 65535);
	}else{
		$datagram = @stream_socket_recvfrom($socket, 65535, 0, $from);
		if($datagram !== false && $datagram !== "" && $peer === null){
			$peer = $from;
			//the first datagram tells us where to answer, so replay it now the address is known
		}
	}

	if($datagram !== false && $datagram !== ""){
		$connection->handle($datagram);
	}else{
		$connection->handleTimeout();
	}

	if($established && !$sent){
		$connection->send("hello from altay dtls\n");
		$sent = true;
		echo "  app data out\n";
	}

	if($sent && $received !== []){
		break;
	}

	usleep(20000);
}

echo $established ? "ESTABLISHED\n" : "NOT ESTABLISHED\n";
echo "peer fingerprint: " . substr((string) $connection->getPeerFingerprint(), 0, 47) . "\n";

exit($established ? 0 : 1);
