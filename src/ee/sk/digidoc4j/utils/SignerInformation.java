package ee.sk.digidoc4j.utils;

/**
 * Optional additional information about the signer
 */
public class SignerInformation {
  public String city;
  public String stateOrProvince;
  public String postalCode;
  public String countryName;
  public String signerRoles;

  /**
   * empty constructor
   */
  public SignerInformation() {
  }

  /**
   * Constructor
   *
   * @param city            city of the signature location
   * @param stateOrProvince state/province of the signature location
   * @param postalCode      postal code of the signature location
   * @param countryName     country of the signature location
   * @param signerRoles     the signer’s role and optionally the signer’s resolution
   *                        Note that only one signer role value (i.e. one <ClaimedRole> XML element) should be used
   *                        If the signer role contains both role and resolution then they must be separated
   *                        with a slash mark, e.g. “role / resolution”
   *                        Note that when setting the resolution value then role must also be specified
   */
  public SignerInformation(String city, String stateOrProvince, String postalCode, String countryName, String signerRoles) {
    this.city = city;
    this.stateOrProvince = stateOrProvince;
    this.postalCode = postalCode;
    this.countryName = countryName;
    this.signerRoles = signerRoles;
  }
}
