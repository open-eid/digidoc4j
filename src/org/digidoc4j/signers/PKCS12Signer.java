package org.digidoc4j.signers;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import org.digidoc4j.Container;
import org.digidoc4j.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12Signer extends Signer {
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
    return keyEntry.getCertificate();
  }

  @Override
  public final PrivateKey getPrivateKey() {
    logger.debug("");
    return keyEntry.getPrivateKey();
  }

  @Override
  public byte[] sign(Container container, byte[] dataToSign) {
    org.digidoc4j.DigestAlgorithm digestAlgorithm = container.getDigestAlgorithm();
    logger.debug("Digest algorithm: " + digestAlgorithm);
    byte[] sign = signatureTokenConnection.sign(dataToSign, DigestAlgorithm.forXML(digestAlgorithm.toString()),
        keyEntry);
    return sign;
  }


}
