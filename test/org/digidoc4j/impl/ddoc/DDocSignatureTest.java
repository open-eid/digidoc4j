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

import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProductionPlace;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

public class DDocSignatureTest extends DigiDoc4JTestHelper {

  private static DDocFacade container;

  @BeforeClass
  public static void setUp() {
    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setProductionPlace(new SignatureProductionPlace("City", "State", "PostalCode", "Country"));
    signatureParameters.setRoles(asList("Role1"));

    container = new DDocFacade();
    container.setSignatureParameters(signatureParameters);

    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray()));
  }

  @Test
  public void getCity() throws Exception {
    assertEquals("City",  container.getSignature(0).getCity());
  }

  @Test
  public void getCountryName() throws Exception {
    assertEquals("Country",  container.getSignature(0).getCountryName());

  }

  @Test
  public void getPostalCode() throws Exception {
    assertEquals("PostalCode",  container.getSignature(0).getPostalCode());
  }

  @Test
  public void getStateOrProvince() throws Exception {
    assertEquals("State",  container.getSignature(0).getStateOrProvince());
  }

  @Test
  public void getSignerRoles() throws Exception {
    List<String> signerRoles = container.getSignature(0).getSignerRoles();
    assertEquals("Role1", signerRoles.get(0));
  }
}
