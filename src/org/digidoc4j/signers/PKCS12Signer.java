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

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;

import org.digidoc4j.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12Signer implements Signer {
  final Logger logger = LoggerFactory.getLogger(PKCS12Signer.class);
  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;


  /**
   * Constructs PKCS12 signer object. If more than one key is provided only first is used
   *
   * @param fileName .p12 file name and path
   * @param password keystore password
   */
  public PKCS12Signer(String fileName, char[] password) {
    logger.debug("File name: " + fileName);
    signatureTokenConnection = new Pkcs12SignatureToken(password, fileName);
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

  @Override
  public X509Certificate getCertificate() {
    logger.debug("");
    return keyEntry.getCertificate().getCertificate();
  }

  @Override
  public final PrivateKey getPrivateKey() {
    logger.debug("");
    return keyEntry.getPrivateKey();
  }

  @Override
  public byte[] sign(org.digidoc4j.DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    logger.debug("Digest algorithm: " + digestAlgorithm);
    return signatureTokenConnection.sign(dataToSign, DigestAlgorithm.forXML(digestAlgorithm.toString()),
            keyEntry);
  }
}
