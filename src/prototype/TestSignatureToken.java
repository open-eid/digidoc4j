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

import static org.digidoc4j.DigestAlgorithm.SHA256;

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang3.ArrayUtils;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;

public class TestSignatureToken extends PKCS12SignatureToken {

  private static final Logger logger = LoggerFactory.getLogger(TestSignatureToken.class);

  public TestSignatureToken(String fileName, char[] password) {
    super(fileName, password);
  }

  public byte[] sign(byte[] digest) {
    try {
      logger.debug("Signing digest:" + new String(digest, "UTF-8"));
    } catch (UnsupportedEncodingException ignore) {
    }
    final String javaSignatureAlgorithm = "NONEwith" + keyEntry.getEncryptionAlgorithm();
    return null;//DSSUtils.encrypt(javaSignatureAlgorithm, keyEntry.getPrivateKey(), addPadding(digest));
  }

  private byte[] addPadding(byte []digest) {
    return ArrayUtils.addAll(SHA256.digestInfoPrefix(), digest);
  }
}
