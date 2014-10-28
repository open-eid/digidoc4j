package org.digidoc4j;

import org.slf4j.Logger;

import java.io.Serializable;

/**
 * Optional additional information about the signer
 */
public class SignatureProductionPlace implements Serializable {
  Logger logger = org.slf4j.LoggerFactory.getLogger(SignatureProductionPlace.class);
  private String city;
  private String stateOrProvince;
  private String postalCode;
  private String country;

  /**
   * empty constructor
   */
  public SignatureProductionPlace() {
    logger.debug("");
  }

  public SignatureProductionPlace(String city, String stateOrProvince, String postalCode, String country) {
    this.city = city;
    this.stateOrProvince = stateOrProvince;
    this.postalCode = postalCode;
    this.country = country;
  }

  public String getCity() {
    logger.debug("");
    return city;
  }

  public void setCity(String city) {
    logger.debug("City: " + city);
    this.city = city;
  }

  public String getStateOrProvince() {
    logger.debug("");
    return stateOrProvince;
  }

  public void setStateOrProvince(String stateOrProvince) {
    logger.debug("State/province: " + stateOrProvince);
    this.stateOrProvince = stateOrProvince;
  }

  public String getPostalCode() {
    logger.debug("");
    return postalCode;
  }

  public void setPostalCode(String postalCode) {
    logger.debug("Postal code: " + postalCode);
    this.postalCode = postalCode;
  }

  public String getCountry() {
    logger.debug("");
    return country;
  }

  public void setCountry(String country) {
    logger.debug("Country: " + country);
    this.country = country;
  }
}
