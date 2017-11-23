/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;

/**
 * Implements PKCS#11 interface for Smart Cards and hardware tokens.
 * <p/>
 * It can be used for making digital signatures with Smart Cards (ID-Cards), USB tokens (Aladdin USB eToken),
 * HSM (Hardware Security Module) or other hardware tokens that use PKCS#11 API.
 * <p/>
 * PKCS#11 module path depends on your operating system and installed smart card or hardware token library.
 * <p/>
 * If you are using OpenSC (https://github.com/OpenSC/OpenSC/wiki), then <br/>
 * For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll, <br/>
 * For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so, <br/>
 * For OSX, it could be /usr/local/lib/opensc-pkcs11.so <br/>
 */
public class PKCS11SignatureToken implements SignatureToken {

  private static final Logger logger = LoggerFactory.getLogger(PKCS11SignatureToken.class);
  private AbstractSignatureTokenConnection signatureTokenConnection;
  private DSSPrivateKeyEntry privateKeyEntry;
  /**
   * Initializes the PKCS#11 token.
   *
   * @param pkcs11ModulePath PKCS#11 module path, depends on your operating system and installed smart card or hardware token library.
   * @param password         Secret pin code for digital signature.
   * @param slotIndex        Token slot index, depends on the hardware token.
   */
  public PKCS11SignatureToken(String pkcs11ModulePath, char[] password, int slotIndex) {
    logger.debug("Initializing PKCS#11 signature token from " + pkcs11ModulePath + " and slot " + slotIndex);
    signatureTokenConnection = new Pkcs11SignatureToken(pkcs11ModulePath, password, slotIndex);
  }

  /**
   * Initializes the PKCS#11 token with password callback.
   * <p/>
   * This Password Callback is used in order to retrieve the password from the user when accessing the Key Store.
   *
   * @param pkcs11ModulePath PKCS#11 module path, depends on your operating system and installed smart card or hardware token library.
   * @param passwordCallback callback for providing the password for the private key.
   * @param slotIndex        Token slot index, depends on the hardware token.
   */
  public PKCS11SignatureToken(String pkcs11ModulePath, PasswordInputCallback passwordCallback, int slotIndex) {
    logger.debug("Initializing PKCS#11 signature token with password callback from " + pkcs11ModulePath + " and slot " + slotIndex);
    signatureTokenConnection = new Pkcs11SignatureToken(pkcs11ModulePath, passwordCallback, slotIndex);
  }

  /**
   * Fetches the private key entries from the hardware token for information purposes.
   * The actual private key remains on the token and won't be accessible.
   *
   * @return list of private key entries.
   */
  public List<DSSPrivateKeyEntry> getPrivateKeyEntries() {
    return signatureTokenConnection.getKeys();
  }

  /**
   * For selecting a particular private key to be used for signing.
   *
   * @param privateKeyEntry
   */
  public void usePrivateKeyEntry(DSSPrivateKeyEntry privateKeyEntry) {
    this.privateKeyEntry = privateKeyEntry;
  }

  @Override
  public X509Certificate getCertificate() {
    logger.debug("Fetching certificate");
    return getPrivateKeyEntry().getCertificate().getCertificate();
  }

  @Override
  public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    logger.info("Signing with PKCS#11 signature token, using digest algorithm: " + digestAlgorithm.name());
    ToBeSigned toBeSigned = new ToBeSigned(dataToSign);
    eu.europa.esig.dss.DigestAlgorithm dssDigestAlgorithm = eu.europa.esig.dss.DigestAlgorithm.forXML(digestAlgorithm.toString());
    getPrivateKeyEntry();
    SignatureValue signature = signatureTokenConnection.sign(toBeSigned, dssDigestAlgorithm, privateKeyEntry);
    return signature.getValue();
  }

  private DSSPrivateKeyEntry getPrivateKeyEntry() {
    if (privateKeyEntry == null) {
      privateKeyEntry = getPrivateKeyEntries().get(0);
    }
    return privateKeyEntry;
  }
}
