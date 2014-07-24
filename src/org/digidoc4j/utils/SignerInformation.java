package org.digidoc4j.utils;

/**
 * Optional additional information about the signer
 */
public class SignerInformation {
  private String city;
  private String stateOrProvince;
  private String postalCode;
  private String country;

  /**
   * empty constructor
   */
  public SignerInformation() {
  }

  public String getCity() {
    return city;
  }

  public void setCity(String city) {
    this.city = city;
  }

  public String getStateOrProvince() {
    return stateOrProvince;
  }

  public void setStateOrProvince(String stateOrProvince) {
    this.stateOrProvince = stateOrProvince;
  }

  public String getPostalCode() {
    return postalCode;
  }

  public void setPostalCode(String postalCode) {
    this.postalCode = postalCode;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }
}
