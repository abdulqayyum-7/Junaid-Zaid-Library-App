import 'dart:convert';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:http/http.dart' as http;

import '../config/api_constants.dart';
import '../config/koha_service_account.dart';
import 'secure_storage_service.dart';

/// Thrown when Koha rejects credentials or the request fails. Callers
/// show [message] directly — it's already meant to be user-facing.
class KohaAuthException implements Exception {
  final String message;
  const KohaAuthException(this.message);

  @override
  String toString() => message;
}

/// Half of the real login for this app (Updated Authentication
/// Workflow, Phase 3) — the other half is FirebaseAuthService. See
/// EmailLoginScreen, which calls both with the same email + password
/// and requires both to succeed. This class only ever handles the Koha
/// side of that pair.
///
/// CORRECTED (round 2): this used to POST to /api/v1/auth/password
/// expecting a JSON {access_token: ...} response — confirmed via
/// Postman that this endpoint returns 404, it doesn't exist. The real,
/// working endpoint is /api/v1/auth/password/validation.
///
/// CORRECTED (round 2, the actual bug this round fixes): the Basic
/// Auth header on that call was being built from the STUDENT's own
/// username/password. That always fails — Koha bug 36561 confirms
/// /api/v1/auth/password/validation requires the Basic Auth account to
/// hold the `borrowers` permission, which a regular student patron
/// never has. The Basic Auth header must be a dedicated staff
/// "validator" account (see koha_service_account.dart) with only that
/// one permission. The student's own userid/password still go in the
/// JSON body — that's what's actually being checked. Once validated,
/// every LATER Koha call (koha_api_client.dart) goes back to using the
/// student's OWN username/password, which is now confirmed correct —
/// Koha does let a patron access their own records with their own
/// Basic Auth; it's specifically this one validation endpoint that's
/// staff-gated.
class KohaAuthService {
  final http.Client _client;
  final SecureStorageService _secureStorage;

  KohaAuthService({http.Client? client, SecureStorageService? secureStorage})
      : _client = client ?? http.Client(),
        _secureStorage = secureStorage ?? SecureStorageService();

  // DEV-ONLY hardcoded account so the app is reachable without a real
  // Koha server running. Gated behind kDebugMode — this branch is
  // compiled out of release builds entirely (Dart's compiler strips
  // unreachable `if (kDebugMode)` branches in release mode), so it can
  // never work in anything you actually ship, not just "shouldn't"
  // work. Still search this file for "DEV-ONLY" before shipping, to
  // confirm.
  static const _devUsername = 'testuser';
  static const _devPassword = 'test1234';
  static const _devPatronId = '0000';

  /// Logs a student in against Koha, stores the student's own
  /// username+password (see SecureStorageService for why — there is no
  /// token to store instead) and returns the patron ID on success.
  /// Throws [KohaAuthException] with a user-facing message on failure.
  Future<String> login({required String username, required String password}) async {
    if (kDebugMode && username == _devUsername && password == _devPassword) {
      await _secureStorage.saveSession(
        username: _devUsername,
        password: _devPassword,
        patronId: _devPatronId,
      );
      return _devPatronId;
    }

    final uri = Uri.parse(ApiConstants.kohaAuthValidationEndpoint);

    // The Basic Auth header on THIS call is the dedicated staff
    // validator account (borrowers permission only) — NOT the
    // student's credentials. See koha_service_account.dart for why.
    // The student's own userid/password go in the JSON body instead,
    // which is what Koha actually validates.
    final validatorAuthValue = base64Encode(utf8.encode(
      '${KohaServiceAccount.validatorUserid}:${KohaServiceAccount.validatorPassword}',
    ));

    late final http.Response response;
    try {
      response = await _client
          .post(
        uri,
        headers: {
          'Authorization': 'Basic $validatorAuthValue',
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: jsonEncode({'userid': username, 'password': password}),
      )
          .timeout(ApiConstants.requestTimeout);
    } catch (_) {
      throw const KohaAuthException(
        'Could not reach the library server. Check your connection and try again.',
      );
    }

    // A 401/403 here means the VALIDATOR account itself was rejected
    // (wrong/missing staff credentials, or it lost the `borrowers`
    // permission) — not that the student's password is wrong. Surface
    // that distinctly so it isn't confused with a student typo.
    if (response.statusCode == 401 || response.statusCode == 403) {
      throw const KohaAuthException(
        'Library server rejected the app\'s service account. Contact the library admin.',
      );
    }

    // Koha's /auth/password/validation returns 400 with
    // {"error":"Validation failed"} when the student's own
    // userid/password in the body don't match — this is the real
    // "wrong password" case for the student.
    if (response.statusCode == 400) {
      throw const KohaAuthException('Incorrect email or password.');
    }

    if (response.statusCode == 404 || response.statusCode == 405) {
      throw KohaAuthException(
        'The library server does not support this login method '
            '(auth endpoint returned ${response.statusCode}). Confirm '
            '/api/v1/auth/password/validation is enabled on this Koha installation.',
      );
    }

    if (response.statusCode != 200 && response.statusCode != 201) {
      throw KohaAuthException(
        'Login failed (server returned ${response.statusCode}). Please try again later.',
      );
    }

    Map<String, dynamic> data;
    try {
      data = jsonDecode(response.body) as Map<String, dynamic>;
    } catch (_) {
      throw const KohaAuthException('Unexpected response from the library server.');
    }

    // Confirmed real response shape: only ever {cardnumber, patron_id,
    // userid} — no token field of any kind. patron_id is preferred
    // since it's what koha_api_client.dart's future patron-scoped calls
    // (checkouts/holds/fines) will need; cardnumber/userid are
    // fallbacks in case a given Koha config omits patron_id.
    final patronId = (data['patron_id'] ?? data['cardnumber'] ?? data['userid'])?.toString();
    if (patronId == null || patronId.isEmpty) {
      throw const KohaAuthException('Unexpected response from the library server.');
    }

    // From here on, every other Koha call uses the STUDENT's own
    // username/password — now confirmed correct — not the validator
    // account.
    await _secureStorage.saveSession(username: username, password: password, patronId: patronId);
    return patronId;
  }

  Future<void> logout() => _secureStorage.clearSession();

  Future<bool> isLoggedIn() => _secureStorage.hasSession();
}