<?php
/**
 * Encryption utility for IPMI credentials
 * Uses AES-256-CBC encryption
 */

class Encryption {
  private static $key = null;

  /**
   * Heuristic check: value looks like this project's encrypted payload format
   * (base64(iv + openssl_base64_ciphertext)).
   */
  private static function looksLikeEncryptedPayload($value) {
    if (!is_string($value) || $value === '' || strlen($value) < 24) {
      return false;
    }
    if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $value)) {
      return false;
    }
    $decoded = base64_decode($value, true);
    if ($decoded === false || strlen($decoded) < 24) {
      return false;
    }
    $cipherPayload = substr($decoded, 16);
    if ($cipherPayload === '') {
      return false;
    }
    // openssl_encrypt(..., options=0) returns base64-encoded ciphertext text.
    return (bool) preg_match('/^[A-Za-z0-9+\/=]+$/', $cipherPayload);
  }
  
  /**
   * Get encryption key from config
   */
  private static function getKey() {
    if (self::$key === null) {
      if (!defined('ENCRYPTION_KEY') || empty(ENCRYPTION_KEY)) {
        throw new Exception('Encryption key not configured. Set ENCRYPTION_KEY in config.php');
      }
      self::$key = ENCRYPTION_KEY;
      
      // Ensure key is exactly 32 bytes for AES-256
      if (strlen(self::$key) < 32) {
        self::$key = str_pad(self::$key, 32, '0');
      } elseif (strlen(self::$key) > 32) {
        self::$key = substr(self::$key, 0, 32);
      }
    }
    return self::$key;
  }
  
  /**
   * Encrypt a string
   */
  public static function encrypt($plaintext) {
    if (empty($plaintext)) {
      return '';
    }
    
    $key = self::getKey();
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    
    if ($encrypted === false) {
      throw new Exception('Encryption failed');
    }
    
    // Prepend IV to encrypted data
    return base64_encode($iv . $encrypted);
  }
  
  /**
   * Decrypt a string
   */
  public static function decrypt($encrypted) {
    if (empty($encrypted)) {
      return '';
    }
    
    $key = self::getKey();
    $data = base64_decode($encrypted, true);
    
    if ($data === false || strlen($data) < 16) {
      throw new Exception('Invalid encrypted data');
    }
    
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    
    if ($decrypted === false) {
      throw new Exception('Decryption failed');
    }
    
    return $decrypted;
  }

  /**
   * Normalize a credential for DB storage.
   * - Empty stays empty
   * - Plaintext gets encrypted
   * - Already-encrypted-with-current-key stays as-is
   * - Encrypted-like but undecryptable (wrong key/corrupt) is rejected
   */
  public static function normalizeForStorage($value, $fieldName = 'credential') {
    $value = (string)$value;
    if ($value === '') {
      return '';
    }

    try {
      self::decrypt($value);
      return $value; // already encrypted with current key
    } catch (Exception $e) {
      if (self::looksLikeEncryptedPayload($value)) {
        throw new Exception(
          $fieldName . ' appears encrypted but cannot be decrypted with current ENCRYPTION_KEY. ' .
          'Please re-enter plaintext value for this field.'
        );
      }
      return self::encrypt($value);
    }
  }
}
