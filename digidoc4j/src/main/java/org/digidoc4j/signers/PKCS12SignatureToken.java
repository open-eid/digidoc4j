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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12SignatureToken implements SignatureToken {
  private static final Logger logger = LoggerFactory.getLogger(PKCS12SignatureToken.class);
  protected KeyStoreSignatureTokenConnection signatureTokenConnection = null;
  protected KSPrivateKeyEntry keyEntry = null;

  /**
   * Constructs PKCS12 signer object. If more than one key is provided then first NON_REPUDIATION key is used.
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as char array
   */
  public PKCS12SignatureToken(String fileName, char[] password) {
    init(fileName, String.valueOf(password), X509Cert.KeyUsage.NON_REPUDIATION, null);
  }

  /**
   * Constructs PKCS12 signer object. If more than one key is provided then first NON_REPUDIATION key is used.
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as String
   */
  public PKCS12SignatureToken(String fileName, String password) {
    init(fileName, password, X509Cert.KeyUsage.NON_REPUDIATION, null);
  }

  /**
   * Constructs PKCS12 signer object. Key is searched by given alias.
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as String
   * @param alias known key alias
   */
  public PKCS12SignatureToken(String fileName, String password, String alias) {
    init(fileName, password, X509Cert.KeyUsage.NON_REPUDIATION, alias);
  }

  /**
   * Constructs PKCS12 signer object. First key matching given keyUsage is used.
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as String
   * @param keyUsage key usage value, default KeyUsageBit.nonRepudiation
   */
  public PKCS12SignatureToken(String fileName, String password, X509Cert.KeyUsage keyUsage) {
    init(fileName, password, keyUsage, null);
  }

  private void init(String fileName, String password, X509Cert.KeyUsage keyUsage, String alias) {
    logger.info("Using PKCS#12 signature token from file: " + fileName);
    try {
      signatureTokenConnection = new Pkcs12SignatureToken(fileName, password);
    } catch (IOException e) {
      throw new DigiDoc4JException(e.getMessage());
    }
    if (alias != null) {
      logger.debug("Searching key with alias: " + alias);
      keyEntry = signatureTokenConnection.getKey(alias, password);
    } else {
      logger.debug("Searching key by usage: " + keyUsage.name());
      List<DSSPrivateKeyEntry> keys = signatureTokenConnection.getKeys();
      X509CertSelector selector = new X509CertSelector();
      selector.setKeyUsage(getUsageBitArray(keyUsage)); // TODO: Test this!
      for (DSSPrivateKeyEntry key : keys) {
        if (selector.match(key.getCertificate().getCertificate())) {
          keyEntry = (KSPrivateKeyEntry) key;
          break;
        }
      }
    }
    if (keyEntry == null && signatureTokenConnection.getKeys().size() > 0)
      keyEntry = (KSPrivateKeyEntry)signatureTokenConnection.getKeys().get(0);
  }

  private boolean[] getUsageBitArray(X509Cert.KeyUsage keyUsage) {
    sun.security.x509.KeyUsageExtension usage = new sun.security.x509.KeyUsageExtension();
    try {
      usage.set(keyUsage.name(), Boolean.TRUE);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return usage.getBits();
  }

  /**
   * Method for asking DSS signature token connection
   * @return DSS signature token connection
   */
  public KeyStoreSignatureTokenConnection getSignatureTokenConnection() {
    return signatureTokenConnection;
  }

  @Override
  public X509Certificate getCertificate() {
    logger.debug("Using key with alias: ", getAlias());
    return keyEntry.getCertificate().getCertificate();
  }

  @Override
  public byte[] sign(org.digidoc4j.DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    logger.info("Signing with PKCS#12 signature token, using digest algorithm: " + digestAlgorithm.name());
    ToBeSigned toBeSigned = new ToBeSigned(dataToSign);
    eu.europa.esig.dss.DigestAlgorithm dssDigestAlgorithm =
        eu.europa.esig.dss.DigestAlgorithm.forXML(digestAlgorithm.toString());
    SignatureValue signature = signatureTokenConnection.sign(toBeSigned, dssDigestAlgorithm, keyEntry);
    return signature.getValue();
  }

  /**
   * Returns key entry alias in keyStore.
   */
  public String getAlias() {
    return keyEntry.getAlias();
  }
}
