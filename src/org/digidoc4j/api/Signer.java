package org.digidoc4j.api;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import org.digidoc4j.utils.SignerInformation;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public abstract class Signer {
  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;
  private final SignerInformation signerInformation = new SignerInformation();
  private List<String> signerRoles = new ArrayList<String>();

  public X509Cert getCertificate() {
    return new X509Cert(keyEntry.getCertificate());
  }

  public final String getCity() {
    return signerInformation.getCity();
  }

  public final String getCountry() {
    return signerInformation.getCountry();
  }

  public final String getPostalCode() {
    return signerInformation.getPostalCode();
  }

  //TODO this is not good way to pass so many parameters discuss it with SK
  public void setSignatureProductionPlace(final String city, final String stateOrProvince, final String postalCode,
                                          final String country) {
    signerInformation.setCity(city);
    signerInformation.setStateOrProvince(stateOrProvince);
    signerInformation.setPostalCode(postalCode);
    signerInformation.setCountry(country);
  }

  public final String getStateOrProvince() {
    return signerInformation.getStateOrProvince();
  }

  public final List<String> getSignerRoles() {
    return signerRoles;
  }

  public void setSignerRoles(final List<String> signerRolesToSet) {
    signerRoles = signerRolesToSet;
  }

  public SignerInformation getSignerInformation() {
    return signerInformation;
  }

  public final PrivateKey getPrivateKey() {
    return keyEntry.getPrivateKey();
  }

  public byte[] sign(String digestAlgorithm, byte[] dataToSign) {
    return signatureTokenConnection.sign(dataToSign, DigestAlgorithm.forXML(digestAlgorithm), keyEntry);
  }
}
