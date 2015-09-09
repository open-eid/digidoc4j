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

import eu.europa.ec.markt.dss.DSSUtils;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.utils.DigestInfoPrefix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

public class TestSignatureToken extends PKCS12SignatureToken {

  final Logger logger = LoggerFactory.getLogger(TestSignatureToken.class);

  public TestSignatureToken(String fileName, char[] password) {
    super(fileName, password);
  }

  public byte[] sign(byte[] digest) {
    try {
      logger.debug("Signing digest:" + new String(digest, "UTF-8"));
    } catch (UnsupportedEncodingException ignore) {
    }
    final String javaSignatureAlgorithm = "NONEwith" + keyEntry.getEncryptionAlgorithm();
    return DSSUtils.encrypt(javaSignatureAlgorithm, keyEntry.getPrivateKey(), addPadding(digest));
  }

  private byte[] addPadding(byte []digest) {
    return ArrayUtils.addAll(DigestInfoPrefix.SHA256, digest);
  }
}
