package ee.sk.digidoc4j;

import java.util.List;

/**
 * Provides interface for signing documents.
 * Digidoc LIB implements PKCS11, PKCS12, CNG signer class that allows signing with EstId chip card.
 * Other implementations may provide signing implementations with other public-key cryptography systems
 */
public interface Signer {
  /**
   * Returns the signer certificate. Must be reimplemented when subclassing
   */
  public X509Cert getCertificate();


  /**
   * Returns city from signature production place
   */
  public String getCity();


  /**
   * Returns country from signature production place
   */
  public String getCountryName();


  /**
   * Returns postal code from signature production place
   */
  public String getPostalCode();


  /**
   * Sets signature production place according XAdES standard. Note that setting the signature production place is optional
   *
   * @param city
   * @param stateOrProvince
   * @param postalCode
   * @param countryName
   */
  public void setSignatureProductionPlace(String city, String stateOrProvince, String postalCode, String countryName);


  /**
   * Returns state from signature production place
   */
  public String getStateOrProvince();


  /**
   * Returns signer roles
   */
  public List<String> getSignerRoles();


  /**
   * Sets signature roles according XAdES standard. The parameter may contain the signer's role and optionally the signer's resolution. Note that only one signer role value (i.e. one <ClaimedRole> XML element) should be used. If the signer role contains both role and resolution then they must be separated with a slash mark, e.g. 'role / resolution'
   *
   * @param signerRoles
   */
  public void setSignerRoles(List<String> signerRoles);


  /**
   * Signs message digest. Must be reimplemented when subclassing
   *
   * @param method    digest method to be used
   * @param digest    digest to sign
   * @param signature signed result
   * @throws Exception throws exception on error
   */
  public void sign(String method, byte[] digest, byte[] signature) throws Exception;

}