/// Shared-secret AES key used to encrypt a student's password
/// client-side before it's ever written to Firestore (Updated
/// Authentication Workflow, Phase 1 / Step 2).
///
/// ---- Why this changed from RSA to AES ----
/// The previous version used RSA (a public/private keypair): the app
/// only had the PUBLIC key, and only a Cloud Function — running on a
/// server, holding the PRIVATE key in a hidden environment variable —
/// could ever decrypt. That's genuinely stronger, but it requires a
/// server, and a server requires Firebase's paid Blaze plan.
///
/// Without a server, there is nowhere to hide a private key at all —
/// admin-dashboard.html, running in a browser, is the thing doing the
/// decrypting now, and it's a plain HTML file anyone can open and read
/// the source of. So this is now a SINGLE shared secret instead: the
/// same string encrypts (in the app) and decrypts (in
/// admin-dashboard.html). Both sides must have the EXACT same value.
///
/// ---- What this does and doesn't protect against ----
/// This still stops someone casually browsing Firestore's console/data
/// exports from reading a student's plaintext password. It does NOT
/// stop someone who decompiles the app or reads admin-dashboard.html's
/// source from recovering this secret — at that point they'd have the
/// same decryption ability the dashboard has. That's an inherent
/// limit of "no backend, no billing card" — not a bug, just a
/// real tradeoff you already agreed to. Keep admin-dashboard.html off
/// the public internet / undiscoverable, since that page's login
/// (checked against the `admins` Firestore collection) is the actual
/// access gate — this secret is a second layer on top of that, not a
/// replacement for it.
///
/// TODO(Muaaz): this is a real, working value for local testing — NOT
/// a placeholder — generated with `openssl rand -hex 32`. Generate a
/// fresh one before shipping to production the same way, and update it
/// in BOTH this file and admin-dashboard.html's PENDING_PASSWORD_SECRET
/// constant together — they must always match exactly.
class CryptoConstants {
  const CryptoConstants._();

  static const String passwordEncryptionSharedSecret =
      '6c48bf185ec43acc142f2fdad9c30a0a2b6b296d17ab2e691f165c6c3d32f778';
}