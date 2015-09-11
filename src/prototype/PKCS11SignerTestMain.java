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

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;

import java.security.NoSuchAlgorithmException;

public class PKCS11SignerTestMain {

  public static void signWithIDCard() throws NoSuchAlgorithmException {
    Container container = ContainerBuilder.
        aContainer().
        withType("BDOC").
        withDataFile("testFiles/test.txt", "text/plain").
        build();
    SignatureToken pkcs11Signer = new PKCS11Signer("01497".toCharArray());
    Signature signature = SignatureBuilder.
        aSignature().
        withContainer(container).
        withSignatureToken(pkcs11Signer).
        invokeSigning();
    container.addSignature(signature);
    container.saveAsFile("signWithIDCard.ddoc");
  }

  // must be run with parameter -Djava.security.debug=sunpkcs11,pkcs11
  public static void main(String[] args) throws NoSuchAlgorithmException {
    signWithIDCard();
  }
}
