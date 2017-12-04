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
import java.security.cert.X509Certificate;

import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12SignatureToken implements SignatureToken {
  private static final Logger logger = LoggerFactory.getLogger(PKCS12SignatureToken.class);
  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;


  /**
   * Constructs PKCS12 signer object. If more than one key is provided only first is used
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as char array
   */
  //TODO new Constructor with password AS String
  public PKCS12SignatureToken(String fileName, char[] password){
    logger.info("Using PKCS#12 signature token from file: " + fileName);
    try {
      signatureTokenConnection = new Pkcs12SignatureToken(fileName, String.valueOf(password));
    } catch (IOException e) {
      throw new DigiDoc4JException(e.getMessage());
    }
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

  /**
   * Constructs PKCS12 signer object. If more than one key is provided only first is used
   *
   * @param fileName .p12 file name and path
   * @param password keystore password as String
   */
  //TODO new Constructor with password AS String
  public PKCS12SignatureToken(String fileName, String password) {
    logger.info("Using PKCS#12 signature token from file: " + fileName);
    try {
      signatureTokenConnection = new Pkcs12SignatureToken(fileName, password);
    } catch (IOException e) {
      throw new DigiDoc4JException(e.getMessage());
    }
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

  @Override
  public X509Certificate getCertificate() {
    logger.debug("");
    return keyEntry.getCertificate().getCertificate();
  }

  @Override
  public byte[] sign(org.digidoc4j.DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    logger.info("Signing with PKCS#12 signature token, using digest algorithm: " + digestAlgorithm.name());
    ToBeSigned toBeSigned = new ToBeSigned(dataToSign);
    DigestAlgorithm dssDigestAlgorithm = DigestAlgorithm.forXML(digestAlgorithm.toString());
    SignatureValue signature = signatureTokenConnection.sign(toBeSigned, dssDigestAlgorithm, keyEntry);
    return signature.getValue();
  }
}
