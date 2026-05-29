# Secure Coding Guidelines: Mobile Application Security

## 1. Purpose and Scope

This section establishes requirements for the security of mobile applications running on iOS, Android, and cross-platform frameworks. Mobile applications operate under a different threat model than server-side software: the client device is untrusted from the perspective of the backend, the application is distributed widely and can be reverse-engineered, and the platform provides specific security primitives that shall be used correctly.

These guidelines map to OWASP Mobile Application Security Verification Standard (MASVS), OWASP Mobile Top 10, NIST SP 800-163 (Vetting the Security of Mobile Applications), and platform-specific guidance from Apple and Google.

## 2. General Principles

The mobile client is untrusted. Authorization decisions, business rules, and data integrity shall be enforced server-side. The mobile application's role in security is to protect data on the device, authenticate users, communicate securely, and present the application's user-facing behavior.

The mobile application is reverse-engineerable. Obfuscation and integrity checks raise the cost of analysis but do not prevent it. Sensitive logic shall not depend on client-side secrecy.

Mobile applications are deployed to many users on many device configurations, including jailbroken or rooted devices. Defenses shall be layered.

## 3. Normative Requirements

### Storage

Sensitive data shall be stored using platform-provided secure storage:

- iOS: Keychain with appropriate accessibility attributes (`kSecAttrAccessibleWhenUnlocked`, biometric protection for highest sensitivity).
- Android: Android Keystore for keys; EncryptedSharedPreferences or DataStore with encryption for structured data.

Plaintext storage in `NSUserDefaults`, `SharedPreferences`, files on internal storage, or files on external storage is prohibited for credentials, tokens, and other sensitive data.

External storage (`getExternalFilesDir` on Android pre-scoped storage) shall be considered world-readable; sensitive data shall not be placed there.

Backups (iCloud, Google Drive, ADB backup) may include application data. Mark sensitive items as non-backup or place them in storage excluded from backup.

### Communication

All network communication shall use TLS 1.2 or higher with certificate verification. App Transport Security (iOS) and Network Security Configuration (Android) shall enforce this. Exceptions for development domains shall not ship in production builds.

Certificate pinning shall be considered for applications with high-value backend connections. Pinning protects against compromise of public CAs and against TLS-intercepting proxies. Pinning shall include a rotation strategy (multiple pins, backup pins, server-side override path) to avoid bricking the application on certificate rotation.

WebView usage shall load only trusted content. JavaScript bridges (`addJavascriptInterface` on Android, message handlers on iOS) exposing native functionality to web content require careful design; untrusted web content shall not have access to native bridges.

### Authentication

Authentication on the device shall use secure flows:

- OAuth 2.0 / OIDC with PKCE for delegated authentication.
- WebAuthn / passkeys where supported.
- Biometric authentication via platform APIs (BiometricPrompt on Android, LocalAuthentication on iOS) with appropriate fallback.

Credentials in transit per the server-side guidelines. Credentials at rest in the Keychain or Keystore per Storage above.

Tokens shall have appropriate lifetimes per the Session Management guideline. Refresh token rotation shall be implemented.

Biometric authentication is convenience, not strong authentication on a stolen device with the user's biometric. For sensitive operations, additional authentication (PIN, password) shall be required.

### Inter-Process Communication

Android components (Activities, Services, Broadcast Receivers, Content Providers) shall be `exported="false"` unless explicitly intended for cross-application use. Exported components shall validate calling applications via signature-level permissions where appropriate.

Custom URL schemes are not secure for receiving sensitive data; any application can register the same scheme. Use universal/app links (with verified domain ownership) for authentication callbacks and similar.

iOS URL schemes have similar concerns; use Universal Links.

iOS App Groups, Android `android:sharedUserId` (deprecated), and similar shared-state mechanisms shall be reviewed for cross-application exposure.

### Hardening

Code obfuscation shall be applied to reduce reverse-engineering effort: R8/ProGuard on Android, native code obfuscation for iOS where appropriate.

Anti-tamper checks shall be considered for high-stakes applications: jailbreak/root detection, debugger detection, hooking framework detection, app-integrity verification (Play Integrity API on Android, DeviceCheck/App Attest on iOS).

These checks are bypassable by determined attackers. They raise the cost and are appropriate where the cost increase matters. Do not treat them as security boundaries.

Production builds shall not include debug logging or debugging symbols that leak sensitive information. Debug builds shall be clearly distinguished and shall not ship.

### Secrets in the Application

API keys, encryption keys, and other secrets in the application binary shall be considered public. Anything required to be secret shall live on the server.

Where third-party SDK API keys are unavoidable (analytics, push notification, error reporting), they shall be the lowest-privilege key available, scoped to the application's package/bundle ID, and rotatable.

### Privacy

Permissions requested shall be limited to those required. Justification for each permission shall be in the app store listing and on the just-in-time prompt.

Tracking shall comply with platform requirements (App Tracking Transparency on iOS, Google Play user data policies) and applicable regulations (GDPR, CCPA, COPPA).

Background location, microphone, camera, and other sensitive access shall be reviewed for necessity.

### Updates and Distribution

Applications shall be distributable via official app stores (Apple App Store, Google Play). Sideloaded distribution shall be limited to enterprise scenarios with controlled device management.

Update mechanisms shall be platform-native. In-app updates (downloading executable content) are prohibited except via platform-supported mechanisms.

Minimum supported OS versions shall be documented and shall be current enough to receive security updates from the platform vendor.

### Backend Trust

The backend shall not trust the mobile application. All client-supplied data shall be validated server-side per the Input Validation guideline. All authorization decisions shall be server-side per the Access Control guideline.

Client-side validation, business logic, and feature gating are user experience features, not security controls. A user can always bypass client-side checks; the server shall enforce.

## 4. Platform-Specific Guidance

### 4.1 iOS

Use Keychain Services for credential storage:

~~~swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.app",
    kSecAttrAccount as String: account,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: tokenData,
]
SecItemAdd(query as CFDictionary, nil)
~~~

Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for most credentials (or `AfterFirstUnlock...` for background access requirements).

App Transport Security shall not be disabled in production. Exception keys for specific domains shall be reviewed.

For LocalAuthentication, fall back to passcode when biometric fails:

~~~swift
context.evaluatePolicy(.deviceOwnerAuthentication, ...)
~~~

For App Attest, validate attestation server-side.

For Universal Links, configure `apple-app-site-association` on the domain and `Associated Domains` capability in the app.

### 4.2 Android

Use Android Keystore for keys, EncryptedSharedPreferences for structured data:

~~~kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val prefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
~~~

Configure Network Security Configuration in `res/xml/network_security_config.xml` and reference from manifest. Do not allow cleartext for any production domain.

Disable backup of sensitive data with `android:allowBackup="false"` or selective rules in `<full-backup-content>`.

Use BiometricPrompt for biometric authentication, not the deprecated FingerprintManager.

For App Links, configure Digital Asset Links file on the domain and `android:autoVerify="true"` on the intent filter.

R8/ProGuard rules shall remove development-only logging:

~~~
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
}
~~~

### 4.3 Cross-Platform Frameworks

For React Native, Flutter, Xamarin, and similar: native security primitives are accessed through plugins. Verify the plugin uses the platform-native secure storage rather than implementing its own.

JavaScript-based logic in React Native is fully visible after extraction. Sensitive logic remains on the server.

Plugin dependencies follow the same dependency management discipline as other dependencies — pinned versions, vulnerability monitoring, periodic review.

### 4.4 Server-Side for Mobile

The backend for a mobile application shall follow all server-side guidelines in this repository. Additionally:

Token formats shall accommodate mobile constraints — short-lived access tokens with longer-lived refresh tokens, rotation on refresh.

Versioning shall accommodate slow user upgrades. Mobile applications in users' hands may be months or years behind current. The API shall version explicitly and support multiple versions for documented transition periods.

## 5. Verification

Mobile application security testing shall include MASVS-aligned review, static analysis of the application binary (MobSF, Quark, custom rules), dynamic analysis on real or emulated devices (Frida, Objection, runtime hooking), and inspection of network traffic. App store submission review provides additional checks but is not a substitute for in-house assessment. Annual penetration testing of mobile applications and their backends. Reviews of permissions, third-party SDKs, and tracker presence at each release.

## 6. References

- OWASP Mobile Application Security Verification Standard (MASVS)
- OWASP Mobile Application Security Testing Guide (MASTG)
- OWASP Mobile Top 10
- NIST SP 800-163 (Vetting Mobile Apps)
- Apple Platform Security guide
- Android Developer Security best practices
- Google Play Developer Program Policies
