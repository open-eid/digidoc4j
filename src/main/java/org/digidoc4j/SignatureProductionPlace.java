/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Optional additional information about the signer
 * Use {@link org.digidoc4j.SignatureParameters} instead.
 */
public class SignatureProductionPlace implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(SignatureProductionPlace.class);
  private String city;
  private String stateOrProvince;
  private String postalCode;
  private String country;

  /**
   * empty constructor
   */
  public SignatureProductionPlace() {
  }

  public SignatureProductionPlace(String city, String stateOrProvince, String postalCode, String country) {
    this.city = city;
    this.stateOrProvince = stateOrProvince;
    this.postalCode = postalCode;
    this.country = country;
  }

  public String getCity() {
    return city;
  }

  public void setCity(String city) {
    logger.debug("City: " + city);
    this.city = city;
  }

  public String getStateOrProvince() {
    return stateOrProvince;
  }

  public void setStateOrProvince(String stateOrProvince) {
    logger.debug("State/province: " + stateOrProvince);
    this.stateOrProvince = stateOrProvince;
  }

  public String getPostalCode() {
    return postalCode;
  }

  public void setPostalCode(String postalCode) {
    logger.debug("Postal code: " + postalCode);
    this.postalCode = postalCode;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    logger.debug("Country: " + country);
    this.country = country;
  }
}
