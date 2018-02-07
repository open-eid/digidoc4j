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

import org.junit.Assert;
import org.junit.Test;

public class SignatureProductionPlaceTest {

  @Test
  public void setCity() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCity("City");
    Assert.assertEquals("City", signatureProductionPlace.getCity());
  }

  @Test
  public void setStateOrProvince() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setStateOrProvince("StateOrProvince");
    Assert.assertEquals("StateOrProvince", signatureProductionPlace.getStateOrProvince());
  }

  @Test
  public void setPostalCode() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setPostalCode("PostalCode");
    Assert.assertEquals("PostalCode", signatureProductionPlace.getPostalCode());
  }

  @Test
  public void setCountry() throws Exception {
    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
    signatureProductionPlace.setCountry("Country");
    Assert.assertEquals("Country", signatureProductionPlace.getCountry());
  }

}
