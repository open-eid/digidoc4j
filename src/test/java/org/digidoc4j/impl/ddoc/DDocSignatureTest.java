/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.util.Arrays;
import java.util.List;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProductionPlace;
import org.junit.Assert;
import org.junit.Test;

public class DDocSignatureTest extends AbstractTest {

  private DDocFacade container;

  @Test
  public void testSignatureParameters() throws Exception {
    Assert.assertEquals("City", this.container.getSignature(0).getCity());
    Assert.assertEquals("Country", this.container.getSignature(0).getCountryName());
    Assert.assertEquals("PostalCode", this.container.getSignature(0).getPostalCode());
    Assert.assertEquals("State", this.container.getSignature(0).getStateOrProvince());
    List<String> signerRoles = this.container.getSignature(0).getSignerRoles();
    Assert.assertEquals("Role1", signerRoles.get(0));
  }

  @Override
  protected void before() {
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setProductionPlace(new SignatureProductionPlace("City", "State", "PostalCode", "Country"));
    signatureParameters.setRoles(Arrays.asList("Role1"));
    this.container = new DDocFacade();
    this.container.setSignatureParameters(signatureParameters);
    this.container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.container.sign(this.pkcs12SignatureToken);
  }

}
