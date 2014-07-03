package org.digidoc4j.utils;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.X509Cert;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Implements PKCS12 signer.
 */
public class PKCS12Signer implements Signer {


  private final AbstractSignatureTokenConnection pkcs12SignatureToken;
  private final DSSPrivateKeyEntry keyEntry;
  private final SignerInformation signerInformation = new SignerInformation();
  private List<String> signerRoles = new ArrayList<String>();

  /**
   * Constructs PKCS12 signer object. If more than one key is provided only first is used
   *
   * @param fileName .p12 file name and path
   * @param password keystore password
   */
  public PKCS12Signer(String fileName, String password) {
    pkcs12SignatureToken = new Pkcs12SignatureToken(password, fileName);
    keyEntry = pkcs12SignatureToken.getKeys().get(0);
  }

  @Override
  public X509Cert getCertificate() {
    return new X509Cert(keyEntry.getCertificate());
  }

  @Override
  public final String getCity() {
    return signerInformation.getCity();
  }

  @Override
  public final String getCountry() {
    return signerInformation.getCountry();
  }

  @Override
  public final String getPostalCode() {
    return signerInformation.getPostalCode();
  }

  @Override //TODO this is not good way to pass so many parameters discuss it with SK
  public void setSignatureProductionPlace(final String city, final String stateOrProvince, final String postalCode,
                                          final String country) {
    signerInformation.setCity(city);
    signerInformation.setStateOrProvince(stateOrProvince);
    signerInformation.setPostalCode(postalCode);
    signerInformation.setCountry(country);
  }

  @Override
  public final String getStateOrProvince() {
    return signerInformation.getStateOrProvince();
  }

  @Override
  public final List<String> getSignerRoles() {
    return signerRoles;
  }

  @Override
  public void setSignerRoles(final List<String> signerRolesToSet) {
    signerRoles = signerRolesToSet;
  }

  @Override
  public final PrivateKey getPrivateKey() {
    return keyEntry.getPrivateKey();
  }

  @Override
  public byte[] sign(String digestAlgorithm, byte[] dataToSign) {
    return pkcs12SignatureToken.sign(dataToSign, DigestAlgorithm.forXML(digestAlgorithm), keyEntry);
  }

  @Override
  public SignerInformation getSignerInformation() {
    return signerInformation;
  }
}
