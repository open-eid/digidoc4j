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
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DDocSignatureTest extends AbstractTest {

  @Test
  public void testSignatureParameters() throws Exception {
    Container container = new DDocOpener().open("src/test/resources/testFiles/valid-containers/container-with-sig-params.ddoc");
    Signature signature = container.getSignatures().get(0);
    assertEquals("City", signature.getCity());
    assertEquals("Country", signature.getCountryName());
    assertEquals("PostalCode", signature.getPostalCode());
    assertEquals("State", signature.getStateOrProvince());
    List<String> signerRoles = signature.getSignerRoles();
    assertEquals("Role1", signerRoles.get(0));
  }

  @Test
  public void testSignatureExceptionHandling(){
    Container container = new DDocOpener().open("src/test/resources/prodFiles/invalid-containers/Belgia_kandeavaldus_LIV.ddoc");
    Signature signature = container.getSignatures().get(1);
    ValidationResult validationResult = signature.validateSignature();
    assertEquals(3, validationResult.getErrors().size());
    List<DigiDoc4JException> errors = validationResult.getErrors();
    assertEquals("Signers cert not trusted, missing CA cert!", errors.get(0).getMessage());
    assertEquals("Signing certificate issuer information does not match", errors.get(1).getMessage());
    assertEquals("70org.digidoc4j.ddoc.DigiDocException; nested exception is: \n" +
            "\tERROR: 117 - No certificate for responder: 'byName: C=EE,O=AS Sertifitseerimiskeskus,OU=Sertifitseerimisteenused,CN=SK Proxy OCSP Responder 2008,E=pki@sk.ee' found in local certificate store!", errors.get(2).getMessage());
  }

}
