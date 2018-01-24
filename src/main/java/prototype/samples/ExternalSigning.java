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

import static org.digidoc4j.DigestAlgorithm.SHA256;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.lang3.ArrayUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.ExternalSigner;

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
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    SignatureToken externalSigner = new ExternalSigner(getSignerCert()) {
      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {

        // IMPLEMENT YOUR EXTERNAL SIGNING HERE

        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
            keyStore.load(stream, "test".toCharArray());
          }
          PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
          final String javaSignatureAlgorithm = "NONEwith" + privateKey.getAlgorithm();

          return AsyncSigning.encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed");
        }
      }

      private byte[] addPadding(byte[] digest) {
        return ArrayUtils.addAll(SHA256.digestInfoPrefix(), digest);
      }
    };

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(externalSigner).
        invokeSigning();

    container.addSignature(signature);
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
