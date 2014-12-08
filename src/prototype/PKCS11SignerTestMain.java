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
import org.digidoc4j.Signer;

import java.security.NoSuchAlgorithmException;

public class PKCS11SignerTestMain {

  public static void signWithIDCard() throws NoSuchAlgorithmException {
    Container container = Container.create(Container.DocumentType.BDOC);
    Signer pkcs11Signer = new PKCS11Signer("01497".toCharArray());
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(pkcs11Signer);
    container.save("signWithIDCard.ddoc");
  }

  // must be run with parameter -Djava.security.debug=sunpkcs11,pkcs11
  public static void main(String[] args) throws NoSuchAlgorithmException {
    signWithIDCard();
  }
}
