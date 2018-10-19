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

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class DDocSignatureTest extends AbstractTest {

  @Test
  public void testSignatureParameters() throws Exception {
    Container container = new DDocOpener().open("src/test/resources/testFiles/valid-containers/container-with-sig-params.ddoc");
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("City", signature.getCity());
    Assert.assertEquals("Country", signature.getCountryName());
    Assert.assertEquals("PostalCode", signature.getPostalCode());
    Assert.assertEquals("State", signature.getStateOrProvince());
    List<String> signerRoles = signature.getSignerRoles();
    Assert.assertEquals("Role1", signerRoles.get(0));
  }

  @Test
  public void testSignatureExceptionHandling(){
    Container container = new DDocOpener().open("src/test/resources/prodFiles/invalid-containers/Belgia_kandeavaldus_LIV.ddoc");
    Signature signature = container.getSignatures().get(1);
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertEquals(3, validationResult.getErrors().size());
    List<DigiDoc4JException> errors = validationResult.getErrors();
    Assert.assertEquals("Signers cert not trusted, missing CA cert!", errors.get(0).getMessage());
    Assert.assertEquals("Signing certificate issuer information does not match", errors.get(1).getMessage());
    Assert.assertEquals("70org.digidoc4j.ddoc.DigiDocException; nested exception is: \n" +
            "\tERROR: 117 - No certificate for responder: 'byName: C=EE,O=AS Sertifitseerimiskeskus,OU=Sertifitseerimisteenused,CN=SK Proxy OCSP Responder 2008,E=pki@sk.ee' found in local certificate store!", errors.get(2).getMessage());
  }

}
