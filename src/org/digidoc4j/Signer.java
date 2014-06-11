package org.digidoc4j;

import java.security.PrivateKey;
import java.util.List;

import org.digidoc4j.utils.SignerInformation;

/**
 * Provides interface for signing documents.
 * Digidoc LIB implements PKCS11, PKCS12, CNG signer class that allows signing with EstId chip card.
 * Other implementations may provide signing implementations with other public-key cryptography systems
 */
public interface Signer {
  /**
   * Returns the signer certificate. Must be reimplemented when subclassing.
   *
   * @return signer certificate
   */
  X509Cert getCertificate();


  /**
   * Returns the signature production city.
   *
   * @return city
   */
  String getCity();


  /**
   * Returns the signature production country.
   *
   * @return country
   */
  String getCountry();


  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  String getPostalCode();


  /**
   * Sets the signature production place according to the XAdES standard.
   * Note that setting the signature production place is optional.
   *
   * @param city            city
   * @param stateOrProvince state
   * @param postalCode      postal code
   * @param countryName     country name
   */
  void setSignatureProductionPlace(String city, String stateOrProvince, String postalCode, String countryName);


  /**
   * Returns the signature production state.
   *
   * @return state
   */
  String getStateOrProvince();


  /**
   * Returns the roles of the signer.
   *
   * @return signer roles
   */
  List<String> getSignerRoles();


  /**
   * Sets signature roles according to the XAdES standard.
   * The parameter may contain the signer's role and optionally the signer's resolution.
   * Note that only one signer role value (i.e. one <ClaimedRole> XML element) should be used. If the signer role
   * contains both role and resolution then they must be separated with a slash mark, e.g. 'role / resolution'.
   *
   * @param signerRoles signer roles
   */
  void setSignerRoles(List<String> signerRoles);

  /**
   * Returns the private key if possible.
   *
   * @return private key
   */
  PrivateKey getPrivateKey();

  /**
   * Signs the data.
   *
   * @param digestAlgorithm digest algorithm
   * @param dataToSign      data to sign
   * @return signature
   */
  byte[] sign(String digestAlgorithm, byte[] dataToSign);

  /**
   * TODO description
   *
   * @return SignerInformation returns signer information
   */
  public SignerInformation getSignerInformation();
}
