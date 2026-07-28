import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Wraps flutter_secure_storage (Android Keystore / iOS Keychain backed)
/// for the Koha session and, as of Phase 8, a simple guest-mode flag.
/// Guest mode isn't sensitive data, but reusing the same storage
/// instance avoids adding a second persistence mechanism (e.g.
/// shared_preferences) for one boolean.
///
/// CHANGED: this used to store a single Koha "access token". Confirmed
/// against the real Koha 25 instance (via Postman): the working login
/// endpoint, /api/v1/auth/password/validation, never issues a token at
/// all — it's a stateless Basic-Auth-per-request scheme. So there is no
/// token to store anymore; instead this stores the student's own
/// username + password, so KohaApiClient can rebuild the same Basic
/// Auth header on every later request. This is exactly what
/// flutter_secure_storage is for (OS-level encrypted storage) — it's
/// not meaningfully different from storing a token there, just a
/// different pair of strings.
class SecureStorageService {
  static const _usernameKey = 'koha_username';
  static const _passwordKey = 'koha_password';
  static const _patronIdKey = 'koha_patron_id';
  static const _guestModeKey = 'guest_mode';

  final FlutterSecureStorage _storage;

  SecureStorageService({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  Future<void> saveSession({
    required String username,
    required String password,
    required String patronId,
  }) async {
    await _storage.write(key: _usernameKey, value: username);
    await _storage.write(key: _passwordKey, value: password);
    await _storage.write(key: _patronIdKey, value: patronId);
  }

  Future<String?> readUsername() => _storage.read(key: _usernameKey);

  Future<String?> readPassword() => _storage.read(key: _passwordKey);

  Future<String?> readPatronId() => _storage.read(key: _patronIdKey);

  Future<bool> hasSession() async {
    final username = await readUsername();
    final password = await readPassword();
    return (username != null && username.isNotEmpty) && (password != null && password.isNotEmpty);
  }

  Future<void> clearSession() async {
    await _storage.delete(key: _usernameKey);
    await _storage.delete(key: _passwordKey);
    await _storage.delete(key: _patronIdKey);
  }

  // ---- Guest mode (Phase 8) ----

  Future<void> setGuestMode(bool value) async {
    if (value) {
      await _storage.write(key: _guestModeKey, value: 'true');
    } else {
      await _storage.delete(key: _guestModeKey);
    }
  }

  Future<bool> isGuestMode() async {
    final value = await _storage.read(key: _guestModeKey);
    return value == 'true';
  }
}