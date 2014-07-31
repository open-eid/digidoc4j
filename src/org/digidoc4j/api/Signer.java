package org.digidoc4j.api;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import org.digidoc4j.utils.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public abstract class Signer {
  final Logger logger = LoggerFactory.getLogger(Signer.class);
  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;
  private final SignerInformation signerInformation = new SignerInformation();
  private List<String> signerRoles = new ArrayList<String>();

  public X509Cert getCertificate() {
    logger.debug("");
    return new X509Cert(keyEntry.getCertificate());
  }

  public final String getCity() {
    logger.debug("");
    return signerInformation.getCity();
  }

  public final String getCountry() {
    logger.debug("");
    return signerInformation.getCountry();
  }

  public final String getPostalCode() {
    logger.debug("");
    return signerInformation.getPostalCode();
  }

  //TODO this is not good way to pass so many parameters discuss it with SK
  public void setSignatureProductionPlace(final String city, final String stateOrProvince, final String postalCode,
                                          final String country) {
    logger.debug("");
    signerInformation.setCity(city);
    signerInformation.setStateOrProvince(stateOrProvince);
    signerInformation.setPostalCode(postalCode);
    signerInformation.setCountry(country);
  }

  public final String getStateOrProvince() {
    logger.debug("");
    return signerInformation.getStateOrProvince();
  }

  public final List<String> getSignerRoles() {
    logger.debug("");
    return signerRoles;
  }

  public void setSignerRoles(final List<String> signerRolesToSet) {
    logger.debug("");
    signerRoles = signerRolesToSet;
  }

  public SignerInformation getSignerInformation() {
    logger.debug("");
    return signerInformation;
  }

  public final PrivateKey getPrivateKey() {
    logger.debug("");
    return keyEntry.getPrivateKey();
  }

  public byte[] sign(String digestAlgorithm, byte[] dataToSign) {
    logger.debug("");
    byte[] sign = signatureTokenConnection.sign(dataToSign, DigestAlgorithm.forXML(digestAlgorithm), keyEntry);
    logger.debug("Data signed with: " + digestAlgorithm);
    return sign;
  }
}
