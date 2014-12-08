/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package prototype.samples;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.token.Constants;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.ExternalSigner;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * example code
 */
public final class ExternalSigning {

  private ExternalSigning() {
  }

  /**
   * External signing example
   */
  public static void main(String[] args) throws Exception {
    System.setProperty("digidoc4j.mode", "TEST");
    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = Container.create(configuration);
    container.addDataFile("testFiles/test.txt", "text/plain");

    Signer externalSigner = new ExternalSigner(getSignerCert()) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        // IMPLEMENT YOUR EXTERNAL SIGNING HERE
        SignedInfo signedInfo = container.prepareSigning(getSignerCert());
        byte[] digest = signedInfo.getDigest();

        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
            keyStore.load(stream, "test".toCharArray());
          }
          PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
          final String javaSignatureAlgorithm = "NONEwith" + privateKey.getAlgorithm();

          return DSSUtils.encrypt(javaSignatureAlgorithm, privateKey, addPadding(digest));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed");
        }
      }

      private byte[] addPadding(byte[] digest) {
        return ArrayUtils.addAll(Constants.SHA256_DIGEST_INFO_PREFIX, digest);
      }
    };

    container.sign(externalSigner);
    container.save("prototype.bdoc");
  }

  private static X509Certificate getSignerCert() {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try(FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
        keyStore.load(stream, "test".toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }
}
