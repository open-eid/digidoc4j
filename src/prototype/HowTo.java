/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package prototype;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.signers.PKCS12SignatureToken;

public class HowTo {
  public static void main(String[] args) {
    test();
  }

  private static void test() {
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    Signature signature = SignatureBuilder.
        aSignature(container).
        withCity("Nömme").
        withRoles("manakeri").
        withSignatureProfile(SignatureProfile.LT_TM).
        withSignatureToken(new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray())).
        invokeSigning();
    container.addSignature(signature);

    container.saveAsFile("prototype.bdoc");
    ValidationResult result = container.validate();
    System.out.println(result.getReport());
  }
}
