package org.digidoc4j.utils;

import org.slf4j.Logger;

/**
 * Optional additional information about the signer
 */
public class SignerInformation {
  Logger logger = org.slf4j.LoggerFactory.getLogger(SignerInformation.class);
  private String city;
  private String stateOrProvince;
  private String postalCode;
  private String country;

  /**
   * empty constructor
   */
  public SignerInformation() {
    logger.debug("");
  }

  public String getCity() {
    logger.debug("");
    return city;
  }

  public void setCity(String city) {
    logger.debug("");
    this.city = city;
  }

  public String getStateOrProvince() {
    logger.debug("");
    return stateOrProvince;
  }

  public void setStateOrProvince(String stateOrProvince) {
    logger.debug("");
    this.stateOrProvince = stateOrProvince;
  }

  public String getPostalCode() {
    logger.debug("");
    return postalCode;
  }

  public void setPostalCode(String postalCode) {
    logger.debug("");
    this.postalCode = postalCode;
  }

  public String getCountry() {
    logger.debug("");
    return country;
  }

  public void setCountry(String country) {
    logger.debug("");
    this.country = country;
  }
}
