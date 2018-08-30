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

import java.util.List;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Signature;
import org.junit.Assert;
import org.junit.Test;

public class DDocSignatureTest extends AbstractTest {

  private DDocContainer container;

  @Test
  public void testSignatureParameters() throws Exception {
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("City", signature.getCity());
    Assert.assertEquals("Country", signature.getCountryName());
    Assert.assertEquals("PostalCode", signature.getPostalCode());
    Assert.assertEquals("State", signature.getStateOrProvince());
    List<String> signerRoles = signature.getSignerRoles();
    Assert.assertEquals("Role1", signerRoles.get(0));
  }

  @Override
  protected void before() {
    this.container = new DDocOpener().open("src/test/resources/testFiles/valid-containers/container-with-sig-params.ddoc");
  }

}
