package prototype;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.token.Constants;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.signers.PKCS12Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

public class TestSigner extends PKCS12Signer {

  final Logger logger = LoggerFactory.getLogger(TestSigner.class);

  public TestSigner(String fileName, char[] password) {
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
    return ArrayUtils.addAll(Constants.SHA256_DIGEST_INFO_PREFIX, digest);
  }
}
