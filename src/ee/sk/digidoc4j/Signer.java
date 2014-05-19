package ee.sk.digidoc4j;

import java.security.PrivateKey;
import java.util.List;

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
   * Returns city from signature production place
   *
   * @return city
   */
  String getCity();


  /**
   * Returns country from signature production place
   *
   * @return country
   */
  String getCountryName();


  /**
   * Returns postal code from signature production place
   *
   * @return postal code
   */
  String getPostalCode();


  /**
   * Sets signature production place according XAdES standard.
   * Note that setting the signature production place is optional
   *
   * @param city            city
   * @param stateOrProvince state
   * @param postalCode      postal code
   * @param countryName     country name
   */
  void setSignatureProductionPlace(String city, String stateOrProvince, String postalCode, String countryName);


  /**
   * Returns state from signature production place
   *
   * @return state
   */
  String getStateOrProvince();


  /**
   * Returns signer roles
   *
   * @return signer roles
   */
  List<String> getSignerRoles();


  /**
   * Sets signature roles according XAdES standard.
   * The parameter may contain the signer's role and optionally the signer's resolution.
   * Note that only one signer role value (i.e. one <ClaimedRole> XML element) should be used. If the signer role
   * contains both role and resolution then they must be separated with a slash mark, e.g. 'role / resolution'
   *
   * @param signerRoles signer roles
   */
  void setSignerRoles(List<String> signerRoles);


  /**
   * Signs message digest. Must be reimplemented when subclassing
   *
   * @param method digest method to be used
   * @param digest digest to sign
   * @return signed result
   * @throws Exception throws exception on error
   */
  byte[] sign(String method, byte[] digest) throws Exception;

  /**
   * Returns private key if it is possible.
   *
   * @return private key
   */
  PrivateKey getPrivateKey();

  /**
   * @param dataToSign      data to sign
   * @param digestAlgorithm digest algorithm
   * @return signature
   */
  byte[] sign(byte[] dataToSign, String digestAlgorithm);
}
