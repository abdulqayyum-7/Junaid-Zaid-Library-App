import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../config/crypto_constants.dart';

/// Client-side AES-256-CBC encryption for the student's password before
/// it is ever written to Firestore (Updated Authentication Workflow,
/// Phase 1 / Step 2: "The password is encrypted before saving").
///
/// This class can only ENCRYPT. There is deliberately no decrypt()
/// method anywhere in the Flutter app — decryption only happens inside
/// admin-dashboard.html, using the SAME shared secret (see
/// crypto_constants.dart for why this is now a shared secret rather
/// than an RSA keypair, and what that tradeoff actually means).
///
/// Output format (must exactly match admin-dashboard.html's CryptoJS
/// decrypt function, or decryption will silently produce garbage):
///   base64( 16-byte random IV ++ AES-256-CBC ciphertext, PKCS7-padded )
/// The AES key itself is SHA-256(sharedSecret) — 32 bytes, matching
/// AES-256.
class CryptoService {
  final _secureRandom = Random.secure();

  Uint8List _aesKey() {
    final digest = SHA256Digest();
    final secretBytes = Uint8List.fromList(utf8.encode(CryptoConstants.passwordEncryptionSharedSecret));
    final out = Uint8List(digest.digestSize);
    digest.update(secretBytes, 0, secretBytes.length);
    digest.doFinal(out, 0);
    return out;
  }

  Uint8List _randomIv() {
    return Uint8List.fromList(List<int>.generate(16, (_) => _secureRandom.nextInt(256)));
  }

  /// PKCS7-pads [input] out to a multiple of 16 bytes. Even if [input]
  /// is already a multiple of 16, a full extra block of padding is
  /// added — this is correct PKCS7 behavior (the padding must always be
  /// removable unambiguously on decrypt) and matches what CryptoJS's
  /// Pkcs7 padding does automatically on the decrypt side.
  Uint8List _pkcs7Pad(Uint8List input) {
    const blockSize = 16;
    final padLength = blockSize - (input.length % blockSize);
    final padded = Uint8List(input.length + padLength);
    padded.setRange(0, input.length, input);
    for (var i = input.length; i < padded.length; i++) {
      padded[i] = padLength;
    }
    return padded;
  }

  /// Encrypts [plaintext] with AES-256-CBC, returning a base64 string
  /// (IV + ciphertext) ready to store directly in a Firestore document
  /// field.
  String encryptPassword(String plaintext) {
    final key = _aesKey();
    final iv = _randomIv();
    final padded = _pkcs7Pad(Uint8List.fromList(utf8.encode(plaintext)));

    final cipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(key), iv));

    final ciphertext = Uint8List(padded.length);
    var offset = 0;
    while (offset < padded.length) {
      cipher.processBlock(padded, offset, ciphertext, offset);
      offset += 16;
    }

    final combined = Uint8List(iv.length + ciphertext.length)
      ..setRange(0, iv.length, iv)
      ..setRange(iv.length, iv.length + ciphertext.length, ciphertext);

    return base64Encode(combined);
  }
}