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

import java.security.NoSuchAlgorithmException;

import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.signers.PKCS11SignatureToken;

public class PKCS11SignerTestMain {

  /**
   * PKCS#11 module path depends on your operating system and installed smart card or hardware token library.
   *
   * If you are using OpenSC (https://github.com/OpenSC/OpenSC/wiki), then
   * For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
   * For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
   * For OSX, it could be /usr/local/lib/opensc-pkcs11.so
   *
   */
  public static final String PKCS_11_MODULE_PATH = "/usr/local/lib/opensc-pkcs11.so";

  /**
   * Secret pin code for digital signature
   */
  public static final String PIN_CODE = "22975";

  /**
   * Token slot index. Depends on the hardware token. Estonian ID-Card slot index is 2.
   */
  public static final int SLOT_INDEX = 2;

  public static void signWithIDCard() throws NoSuchAlgorithmException {
    Container container = ContainerBuilder.
        aContainer(Constant.BDOC_CONTAINER_TYPE).
        withDataFile("testFiles/test.txt", "text/plain").
        build();
    SignatureToken pkcs11Signer = new PKCS11SignatureToken(PKCS_11_MODULE_PATH, PIN_CODE.toCharArray(), SLOT_INDEX);
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(pkcs11Signer).
        invokeSigning();
    container.addSignature(signature);
    container.saveAsFile("signWithIDCard.ddoc");
  }

  public static void main(String[] args) throws NoSuchAlgorithmException {
    signWithIDCard();
  }
}
