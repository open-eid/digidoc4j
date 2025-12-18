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


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignatureProductionPlaceTest {

  @Test
  public void setCity() {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCity("City");
    assertEquals("City", signatureProductionPlace.getCity());
  }

  @Test
  public void setStateOrProvince() {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setStateOrProvince("StateOrProvince");
    assertEquals("StateOrProvince", signatureProductionPlace.getStateOrProvince());
  }

  @Test
  public void setPostalCode() {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setPostalCode("PostalCode");
    assertEquals("PostalCode", signatureProductionPlace.getPostalCode());
  }

  @Test
  public void setCountry() {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCountry("Country");
    assertEquals("Country", signatureProductionPlace.getCountry());
  }

}
