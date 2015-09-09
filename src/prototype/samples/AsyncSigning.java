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
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.ContainerFacade;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.ExternalSigner;
import org.digidoc4j.utils.DigestInfoPrefix;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Example for asynchronous signing
 */
public class AsyncSigning {

  public static void main(String[] args) throws IOException, ClassNotFoundException {
    System.setProperty("digidoc4j.mode", "TEST");

    ContainerFacade container = ContainerFacade.create();
    container.addDataFile("testFiles/test.txt", "text/plain");

    X509Certificate signerCert = getSignerCert();

    SignedInfo signedInfo = container.prepareSigning(signerCert);

    serialize(container);

    //getSignature
    byte[] signature = getExternalSignature(signerCert, signedInfo);

    ContainerFacade deserializedContainer = deserializer();
    deserializedContainer.signRaw(signature);
    deserializedContainer.save("deserializedContainer.bdoc");

    //serialize container
    serialize(deserializedContainer);
  }

  private static byte[] getExternalSignature(X509Certificate signerCert, SignedInfo prepareSigningSignature) {
    SignatureToken externalSigner = new ExternalSigner(signerCert) {
      @Override
      public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
        try {
          KeyStore keyStore = KeyStore.getInstance("PKCS12");
          try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
            keyStore.load(stream, "test".toCharArray());
          }
          PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
          final String javaSignatureAlgorithm = "NONEwith" + privateKey.getAlgorithm();

          return DSSUtils.encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed");
        }
      }

      private byte[] addPadding(byte[] digest) {
        return ArrayUtils.addAll(DigestInfoPrefix.SHA256, digest);
      }

    };

    return externalSigner.sign(prepareSigningSignature.getDigestAlgorithm(), prepareSigningSignature.getDigest());
  }

  private static X509Certificate getSignerCert() {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
        keyStore.load(stream, "test".toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }

  private static void serialize(ContainerFacade container) throws IOException {

    FileOutputStream fileOut = new FileOutputStream("container.bin");
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(container);
    out.flush();
    out.close();
    fileOut.close();
  }

  private static ContainerFacade deserializer() throws IOException, ClassNotFoundException {
    FileInputStream fileIn = new FileInputStream("container.bin");
    ObjectInputStream in = new ObjectInputStream(fileIn);

    ContainerFacade container = (ContainerFacade) in.readObject();

    in.close();
    fileIn.close();

    return container;
  }

}
