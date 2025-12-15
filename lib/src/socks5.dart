import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart' show StreamQueue;
import 'package:dartssh2/src/ssh_forward.dart';

/// Represents a parsed SOCKS5 CONNECT request.
///
/// Contains the destination [host] and [port] requested by the client.
class Socks5Request {
  final String host;
  final int port;

  Socks5Request(this.host, this.port);
}

/// Handles a single SOCKS5 client session over a TCP socket.
///
/// This class implements:
/// - SOCKS5 handshake (NO AUTH)
/// - CONNECT command parsing
/// - IPv4, Domain name and IPv6 address support
/// - Bidirectional relaying between the client and an SSH forward channel
///
/// It does **not** support:
/// - Authentication methods other than NO AUTH
/// - BIND or UDP ASSOCIATE commands
class Socks5Session {
  /// Underlying TCP socket connected to the SOCKS client.
  final Socket socket;

  /// StreamQueue used to read socket data sequentially
  /// without double-listening to the stream.
  final StreamQueue<Uint8List> queue;

  bool _clientClosed = false;

  Socks5Session(this.socket) : queue = StreamQueue(socket);

  /// Performs the SOCKS5 handshake and reads the CONNECT request.
  ///
  /// Returns a [Socks5Request] containing the destination host and port.
  Future<Socks5Request> accept() async {
    await _handshake();
    return _readConnect();
  }

  /// Relays traffic between the SOCKS client and an SSH forward channel.
  ///
  /// Data is forwarded bidirectionally until either side closes the connection.
  Future<void> relay(SSHForwardChannel forward) async {
    _pipeSshToClient(forward);
    await _pipeClientToSsh(forward);
  }

  /// Sends a SOCKS5 error reply to the client and flushes the socket.
  ///
  /// This method is used when a SOCKS5 request cannot be fulfilled
  /// (for example: connection failure, unsupported command, or network
  /// unreachable).
  ///
  /// The [code] must be a valid SOCKS5 reply code as defined in RFC 1928:
  ///
  ///  - 0x01: General SOCKS server failure
  ///  - 0x02: Connection not allowed by ruleset
  ///  - 0x03: Network unreachable
  ///  - 0x04: Host unreachable
  ///  - 0x05: Connection refused
  ///  - 0x06: TTL expired
  ///  - 0x07: Command not supported
  ///  - 0x08: Address type not supported
  ///
  /// A dummy IPv4 address (0.0.0.0:0) is sent in the reply as allowed
  /// by the protocol when the connection was not established.
  ///
  /// Any socket write errors are intentionally ignored, since the client
  /// may have already closed the connection.
  Future<void> replyError(int code) async {
    try {
      socket.add([
        0x05, // VER: SOCKS5
        code, // REP: error code
        0x00, // RSV
        0x01, // ATYP: IPv4 (dummy)
        0, 0, 0, 0, // BND.ADDR = 0.0.0.0
        0, 0, // BND.PORT = 0
      ]);
      await socket.flush();
    } catch (_) {
      // Ignore write failures (client may have already disconnected)
    }
  }

  /// Performs the SOCKS5 handshake.
  ///
  /// Only SOCKS version 5 with "NO AUTHENTICATION" is supported.
  Future<void> _handshake() async {
    final data = await queue.next.timeout(
      const Duration(seconds: 10),
      onTimeout: () {
        throw Exception('SOCKS handshake timeout');
      },
    );

    if (data.length < 2 || data[0] != 0x05) {
      throw Exception('Invalid SOCKS version');
    }

    final nMethods = data[1];
    if (data.length < 2 + nMethods) {
      throw Exception('Invalid SOCKS handshake length');
    }

    final methods = data.sublist(2, 2 + nMethods);

    // We only support NO AUTH (0x00)
    if (!methods.contains(0x00)) {
      // No acceptable authentication methods
      socket.add([0x05, 0xFF]);
      await socket.flush();
      throw Exception('No acceptable authentication method');
    }

    // Accept NO AUTH
    socket.add([0x05, 0x00]);
    await socket.flush();
  }

  /// Reads and parses a SOCKS5 CONNECT request.
  ///
  /// Supported address types:
  /// - IPv4
  /// - Domain name
  /// - IPv6
  ///
  /// Throws if an unsupported command or address type is received.
  Future<Socks5Request> _readConnect() async {
    final req = await queue.next;

    if (req.length < 7 || req[1] != 0x01) {
      throw Exception('Only CONNECT command is supported');
    }

    int offset = 4;
    final atyp = req[3];
    late String host;

    // IPv4
    if (atyp == 0x01) {
      host = req.sublist(offset, offset + 4).join('.');
      offset += 4;
    }
    // Domain name
    else if (atyp == 0x03) {
      final len = req[offset++];
      host = String.fromCharCodes(req.sublist(offset, offset + len));
      offset += len;
    }
    // IPv6
    else if (atyp == 0x04) {
      final bytes = req.sublist(offset, offset + 16);
      offset += 16;
      host = _ipv6FromBytes(bytes);
    } else {
      throw Exception('Unsupported ATYP: $atyp');
    }

    final port = (req[offset] << 8) | req[offset + 1];
    return Socks5Request(host, port);
  }

  /// Sends a successful SOCKS5 reply to the client.
  ///
  /// The bound address is reported as 0.0.0.0:0 since the proxy does not
  /// expose a real bind endpoint.
  Future<void> replySuccess() async {
    socket.add([
      0x05, // SOCKS5
      0x00, // succeeded
      0x00, // reserved
      0x01, // IPv4
      0, 0, 0, 0, // 0.0.0.0
      0, 0, // port 0
    ]);
    await socket.flush();
  }

  /// Pipes data from the SSH forward channel to the SOCKS client.
  void _pipeSshToClient(SSHForwardChannel forward) {
    forward.stream.listen(
      (data) {
        if (!_clientClosed) {
          socket.add(data);
        }
      },
      onDone: () async {
        await socket.close();
      },
    );
  }

  /// Pipes data from the SOCKS client to the SSH forward channel.
  ///
  /// When the client closes the connection, the SSH channel is closed
  /// gracefully.
  Future<void> _pipeClientToSsh(SSHForwardChannel forward) async {
    while (await queue.hasNext) {
      forward.sink.add(await queue.next);
    }

    _clientClosed = true;
    await forward.close();
  }

  /// Converts a 16-byte IPv6 address into its textual representation.
  String _ipv6FromBytes(List<int> bytes) {
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    return hex
        .replaceAllMapped(RegExp('.{4}'), (m) => '${m.group(0)}:')
        .replaceFirst(RegExp(r':$'), '');
  }
}

enum Socks5Reply {
  ///  - 0x01: General SOCKS server failure
  generalFailure(0x01),

  ///  - 0x02: Connection not allowed by ruleset
  connectionNotAllowed(0x02),

  ///  - 0x03: Network unreachable
  networkUnreachable(0x03),

  ///  - 0x04: Host unreachable
  hostUnreachable(0x04),

  ///  - 0x05: Connection refused
  connectionRefused(0x05),

  ///  - 0x06: TTL expired
  ttlExpired(0x06),

  ///  - 0x07: Command not supported
  commandNotSupported(0x07),

  ///  - 0x08: Address type not supported
  addressTypeNotSupported(0x08);

  final int code;
  const Socks5Reply(this.code);
}
