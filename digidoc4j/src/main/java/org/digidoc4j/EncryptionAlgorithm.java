/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

public enum EncryptionAlgorithm {
  RSA,
  RSASSA_PSS,
  ECDSA;

  public static boolean isRsa(EncryptionAlgorithm encryptionAlgorithm) {
    return encryptionAlgorithm == RSA || encryptionAlgorithm == RSASSA_PSS;
  }

  public static boolean isRsaPkcs1(EncryptionAlgorithm encryptionAlgorithm) {
    return encryptionAlgorithm == RSA;
  }

  public static boolean isRsassaPss(EncryptionAlgorithm encryptionAlgorithm) {
    return encryptionAlgorithm == RSASSA_PSS;
  }

  public static boolean isEcdsa(EncryptionAlgorithm encryptionAlgorithm) {
    return encryptionAlgorithm == ECDSA;
  }
}
