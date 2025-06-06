import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';

import 'package:DocLockBox/auth_manager.dart';
import 'package:DocLockBox/doclockbox_rotation.dart';
import 'package:DocLockBox/doclockbox_service.dart';
import 'package:DocLockBox/key_cache_manager.dart';
import 'package:DocLockBox/log_service.dart';
import 'package:DocLockBox/constants.dart';
import 'package:DocLockBox/main.dart';
import 'package:DocLockBox/recover_setup_screen.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

/// Onboarding screen to prompt user for a passphrase.
/// - If it's the first time, it initializes the vault.
/// - After unlock, navigates to the DocLockBoxHome UI.
class DocLockBoxOnboarding extends StatefulWidget {
  final bool bypass;
  final bool resetPassword;
  final DocLockBoxService? docLockBoxService;

  const DocLockBoxOnboarding({
    super.key,
    this.bypass = false,
    this.resetPassword = false,
    this.docLockBoxService,
  });

  @override
  State<DocLockBoxOnboarding> createState() => _DocLockBoxOnboardingState();
}

// UPDATE: Enhanced Onboarding with Passphrase Help + Validation

// Enhanced DocLockBoxOnboarding with improved layout and design

class _DocLockBoxOnboardingState extends State<DocLockBoxOnboarding> {
  final TextEditingController _passphraseController = TextEditingController();
  final TextEditingController _confirmPassphraseController =
      TextEditingController();
  String? _error;
  bool _obscure = true;
  bool _confirmObscure = true;
  bool _isFirstTime = false;
  bool _isLoading = false;
  bool _bypass = true;

  @override
  void initState() {
    super.initState();
    _checkIfVaultExists();
    _bypass = widget.bypass;
    if (widget.bypass && !widget.resetPassword && !_isFirstTime) {
      _unlockWithStoredPassphrase(); // Called only when biometric passed
    }
  }

  Future<void> _checkIfVaultExists() async {
    final vault = DocLockBoxService(
      passphrase: 'placeholder',
    ); // placeholder just to resolve vaultPath
    final directory = await vault.getMetadataDir();
    final iniMetaFile = File('${directory.path}/.doclockbox.ini');
    bool validIniExists = true;
    if (iniMetaFile.existsSync()) {
      final iniData = await iniMetaFile.readAsString();
      final String iniStr = 'Welcome to DocLockBox!';
      Digest hash = sha256.convert(utf8.encode(iniStr));
      validIniExists = hash.toString() == iniData;
      log.i("🔐 ini version file exists: ${iniMetaFile.path}");
    } else {
      log.i("🔐 KEK version file does not exist: ${iniMetaFile.path}");
    }
    setState(() {
      _isFirstTime = !iniMetaFile.existsSync() || !validIniExists;
    });
  }

  Future<void> _unlockWithStoredPassphrase() async {
    try {
      print("🔐 Unlocking with stored passphrase using secure storage");
      final passphrase =
          await AuthManager.getLastUsedPassphrase(); // From secure storage
      if (passphrase == null) {
        setState(() {
          _error = 'Unable to auto-unlock: passphrase missing';
          _bypass = false;
        });
        return;
      }

      final vault = DocLockBoxService(passphrase: passphrase);
      await vault.checkAndRotateIfNeeded();
      await AuthManager.recordUnlockTime();

      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => DocLockBoxHome(vault: vault)),
      );
    } catch (e) {
      setState(() {
        _error = 'Biometric passed but unlock failed: $e';
        _bypass = false;
      });
      log.e("🔐 Error unlocking with stored passphrase: $e");
    }
  }

  bool _isValidPassphrase(String pass) {
    final hasUpper = RegExp(r'[A-Z]').hasMatch(pass);
    final hasLower = RegExp(r'[a-z]').hasMatch(pass);
    final hasNumber = RegExp(r'[0-9]').hasMatch(pass);
    final hasSpecial = RegExp(r'[!@#\\$%^&*(),.?":{}|<>]').hasMatch(pass);
    final isLongEnough = pass.length >= minPassphraseLength;
    final noConsecutive =
        !RegExp(
          r'(abc|bcd|cde|def|123|234|345|456)',
        ).hasMatch(pass.toLowerCase());
    final noRepeat = !RegExp(r'(.)\1{2,}').hasMatch(pass);
    return isLongEnough &&
        hasUpper &&
        hasLower &&
        hasNumber &&
        hasSpecial &&
        noConsecutive &&
        noRepeat;
  }

  Future<void> _unlockVault() async {
    log.i("validating passphrase");
    // setState(() => _isLoading = true);
    setState(() => _error = null);
    VaultKeyCacheManager().clear();
    final pass = _passphraseController.text.trim();
    final confirm = _confirmPassphraseController.text.trim();

    if (_isFirstTime || widget.resetPassword) {
      if (pass != confirm) {
        setState(() => _error = 'Passphrases do not match.');
        return;
      }
      if (!_isValidPassphrase(pass)) {
        setState(
          () =>
              _error =
                  'Passphrase must be $minPassphraseLength+ chars, include uppercase, number, special char, no repeats.',
        );
        return;
      }
    }

    final vault = DocLockBoxService(passphrase: pass);
    if (_isFirstTime) {
      log.i("🔐 First time setup with passphrase");
      await vault.initializeIfMissing();
      await vault.checkAndRotateIfNeeded();
      await AuthManager.recordUnlockTime();
      await AuthManager.setLastUsedPassphrase(pass);
    } else if (widget.resetPassword) {
      log.i("🔐 Resetting passphrase");
      await widget.docLockBoxService?.completePreviousKEKRotation();
      final Map<String, dynamic>? existingKEKVersions =
          await widget.docLockBoxService?.getKEKVersions();
      if (existingKEKVersions == null) {
        setState(() => _error = 'Unable to retrieve KEK versions.');
        return;
      }
      // print("existing KEK versions: $existingKEKVersions");

      // print("🔐 Resetting passphrase with existing KEK versions and new passphrase: ${vault.passphrase} and old passphrase:${widget.lockBoxService?.passphrase}");
      VaultKeyCacheManager().clear();

      await vault.rotateKeys(
        prePopulatedOldKekVersions: existingKEKVersions ?? {},
        shouldCompletePreviosKEK: false,
      );
      await AuthManager.setLastUsedPassphrase(pass);
    } else {
      try {
        final bool isPassphraseValid =
            _isValidPassphrase(pass) && await vault.validatePassphrase(pass);
        if (!isPassphraseValid) {
          setState(() => _error = 'Invalid passphrase, please try again.');
          return;
        }
        log.i(
          "since validation successful for passphrase storing it in secure storage",
        );

        if (widget.bypass) {
          await AuthManager.setLastUsedPassphrase(pass);
        }
        await AuthManager.recordUnlockTime();
      } catch (e, stacktrace) {
        log.e("Error validating passphrase: $e and stacktrace: $stacktrace");
        setState(() => _error = 'Unlock failed: $e , please try again!!');
        return;
      }
    }
    // await vault.initializeIfMissing();
    log.i("validation successful for passphrase");
    // Navigator.of(context).pushReplacement(
    //   MaterialPageRoute(builder: (_) => DocLockBoxHome(vault: vault)),
    // );

    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => DocLockBoxHome(vault: vault)),
      (Route<dynamic> route) => false,
    );
  }

  int _attemptCount = 0;
  String buttonText = 'Unlock Vault';

  @override
  Widget build(BuildContext context) {
    if (_bypass) {
      return const Center(child: CircularProgressIndicator());
    }
    if (!_isFirstTime && !widget.resetPassword) {
      return Scaffold(
        backgroundColor: Colors.grey.shade900,
        appBar: AppBar(
          backgroundColor: Colors.black87,
          title: const Text("🔐 DocLockBox"),
        ),
        body: Center(
          child: SingleChildScrollView(
            child: Container(
              constraints: const BoxConstraints(maxWidth: 480),
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
              decoration: BoxDecoration(
                color: Colors.grey.shade800,
                borderRadius: BorderRadius.circular(16),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.3),
                    blurRadius: 12,
                    offset: const Offset(0, 6),
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    "👋 Welcome to DocLockBox!",
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 20),
                  AbsorbPointer(
                    absorbing: _isLoading,
                    child: TextField(
                      controller: _passphraseController,
                      obscureText: _obscure,
                      onChanged: (_) => setState(() => _error = null),
                      decoration: InputDecoration(
                        filled: true,
                        fillColor: Colors.grey.shade700,
                        labelText: 'Enter Passphrase',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                        suffixIcon: IconButton(
                          icon: Icon(
                            _obscure ? Icons.visibility_off : Icons.visibility,
                          ),
                          onPressed: () => setState(() => _obscure = !_obscure),
                        ),
                      ),
                    ),
                  ),
                  AnimatedSwitcher(
                    duration: const Duration(milliseconds: 300),
                    child:
                        _error != null
                            ? Padding(
                              key: ValueKey(_error),
                              padding: const EdgeInsets.only(top: 8),
                              child: Text(
                                _error!,
                                style: const TextStyle(
                                  color: Colors.red,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            )
                            : const SizedBox(height: 24),
                  ),
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor:
                            _isLoading ? Colors.grey : Colors.blueAccent,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                      onPressed:
                          _isLoading
                              ? null
                              : () async {
                                setState(() {
                                  _isLoading = true;
                                  _error = null;
                                  _attemptCount++;
                                  buttonText = 'Checking...';
                                });
                                try {
                                  await _unlockVault();
                                } catch (e) {
                                  HapticFeedback.vibrate();
                                } finally {
                                  setState(() {
                                    _isLoading = false;
                                    buttonText = 'Try Again ($_attemptCount)';
                                  });
                                }
                              },
                      child:
                          _isLoading
                              ? Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: const [
                                  SizedBox(
                                    width: 18,
                                    height: 18,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: Colors.white,
                                    ),
                                  ),
                                  SizedBox(width: 10),
                                  Text('Checking...'),
                                ],
                              )
                              : Text(
                                buttonText,
                                style: const TextStyle(fontSize: 16),
                              ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  FutureBuilder<String?>(
                    future: RecoveryEmailUtil.read(),
                    builder: (context, snapshot) {
                      final recoveryEmail = snapshot.data;
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          const SizedBox(height: 24),
                          if (recoveryEmail != null && recoveryEmail.isNotEmpty)
                            Align(
                              alignment: Alignment.centerRight,
                              child: GestureDetector(
                                onTap: () {
                                  Navigator.of(context).push(
                                    MaterialPageRoute(
                                      builder:
                                          (_) => RecoverVerifyScreen(
                                            isSetup: false,
                                          ),
                                    ),
                                  );
                                },
                                child: Text(
                                  "Forgot passphrase? Recover",
                                  style: TextStyle(
                                    color: Colors.blueAccent.shade100,
                                    fontSize: 16,
                                    decoration: TextDecoration.underline,
                                  ),
                                ),
                              ),
                            ),
                        ],
                      );
                    },
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.grey.shade900,
      appBar: AppBar(
        backgroundColor: Colors.black87,
        title: const Text("🔐 DocLockBox"),
      ),
      body: Center(
        child: SingleChildScrollView(
          child: Container(
            constraints: const BoxConstraints(maxWidth: 480),
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
            decoration: BoxDecoration(
              color: Colors.grey.shade800,
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.3),
                  blurRadius: 12,
                  offset: const Offset(0, 6),
                ),
              ],
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  "👋 Welcome to DocLockBox!",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 8),
                const Text("Set a strong passphrase to protect your vault."),
                const SizedBox(height: 16),
                const SizedBox(height: 8),
                Text("• At least $minPassphraseLength characters"),
                const Text("• At least one uppercase letter"),
                const Text("• At least one lowercase letter"),
                const Text("• At least one number"),
                const Text("• At least one special character (!@#\$...)"),
                const Text(
                  "• No repeating characters or sequences (abc, 123...)",
                ),
                const SizedBox(height: 20),
                AbsorbPointer(
                  absorbing: _isLoading,
                  child: TextField(
                    controller: _passphraseController,
                    obscureText: _obscure,
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: Colors.grey.shade700,
                      labelText:
                          _isFirstTime ? 'New Passphrase' : 'Enter Passphrase',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _obscure ? Icons.visibility_off : Icons.visibility,
                        ),
                        onPressed: () => setState(() => _obscure = !_obscure),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                AbsorbPointer(
                  absorbing: _isLoading,
                  child: TextField(
                    controller: _confirmPassphraseController,
                    obscureText: _confirmObscure,
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: Colors.grey.shade700,
                      labelText: 'Confirm Passphrase',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _confirmObscure
                              ? Icons.visibility_off
                              : Icons.visibility,
                        ),
                        onPressed:
                            () => setState(
                              () => _confirmObscure = !_confirmObscure,
                            ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                AnimatedSwitcher(
                  duration: const Duration(milliseconds: 300),
                  child:
                      _error != null
                          ? Text(
                            _error!,
                            key: ValueKey(_error),
                            style: const TextStyle(
                              color: Colors.red,
                              fontWeight: FontWeight.w600,
                            ),
                          )
                          : const SizedBox.shrink(),
                ),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blueAccent,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    onPressed:
                        _isLoading
                            ? null
                            : () async {
                              setState(() {
                                _isLoading = true;
                                _error = null;
                              });
                              try {
                                await _unlockVault();
                              } finally {
                                setState(() => _isLoading = false);
                              }
                            },
                    child:
                        _isLoading
                            ? Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: const [
                                SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                ),
                                SizedBox(width: 10),
                                Text('Please wait...'),
                              ],
                            )
                            : const Text(
                              'Unlock / Setup Vault',
                              style: TextStyle(fontSize: 16),
                            ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
