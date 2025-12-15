import 'dart:async';
import 'dart:io';
import 'package:dartssh2/dartssh2.dart';

Future<void> main() async {
  final socket = await SSHSocket.connect('localhost', 22);

  final client = SSHClient(
    socket,
    username: 'root',
    onPasswordRequest: () {
      stdout.write('Password: ');
      stdin.echoMode = false;
      return stdin.readLineSync() ?? exit(1);
    },
  );

  await client.authenticated;

  final serverSocket = await ServerSocket.bind('127.0.0.1', 1080);

  print('Listening on ${serverSocket.address.address}:${serverSocket.port}');

  await for (final socket in serverSocket) {
    unawaited(client.forwardDynamic(socket));
  }

  client.close();
  await client.done;
}
