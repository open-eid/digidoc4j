package prototype.samples;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.token.Constants;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
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
    Container container = Container.create();
    container.setConfiguration(configuration);
    container.addDataFile("testFiles/test.txt", "text/plain");

    Signer externalSigner = new ExternalSigner(getSignerCert()) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
        // IMPLEMENT YOUR EXTERNAL SIGNING HERE
        byte[] digest = calculateDigest(container, dataToSign);

        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          keyStore.load(new FileInputStream("testFiles/signout.p12"), "test".toCharArray());
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
      keyStore.load(new FileInputStream("testFiles/signout.p12"), "test".toCharArray());
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }
}
