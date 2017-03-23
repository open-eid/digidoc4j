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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.ExternalSigner;

/**
 * Example for asynchronous signing
 */
public class AsyncSigning {

  public static void main(String[] args) throws IOException, ClassNotFoundException {
    System.setProperty("digidoc4j.mode", "TEST");

    Container container = ContainerBuilder.
        aContainer().
        withDataFile("testFiles/test.txt", "text/plain").
        build();

    X509Certificate signerCert = getSignerCert();

    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signerCert).
        buildDataToSign();

    serialize(container, "container.bin");
    serialize(dataToSign, "dataToSign.bin");

    //getEntry
    byte[] signatureValue = getExternalSignature(signerCert, dataToSign);

    Container deserializedContainer = deserializer("container.bin");
    DataToSign deserializedDataToSign = deserializer("dataToSign.bin");

    Signature signature = deserializedDataToSign.finalize(signatureValue);
    deserializedContainer.addSignature(signature);
    deserializedContainer.saveAsFile("deserializedContainer.bdoc");

    //serialize container
    serialize(deserializedContainer, "container.bin");
    serialize(deserializedDataToSign, "dataToSign.bin");
  }

  private static byte[] getExternalSignature(X509Certificate signerCert, DataToSign dataToSign) {
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

          return encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign));
        } catch (Exception e) {
          throw new DigiDoc4JException("Loading private key failed");
        }
      }

      private byte[] addPadding(byte[] digest) {
        return ArrayUtils.addAll(SHA256.digestInfoPrefix(), digest);
      }

    };

    return externalSigner.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDigestToSign());
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

  private static <T> void serialize(T container, String path) throws IOException {

    FileOutputStream fileOut = new FileOutputStream(path);
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(container);
    out.flush();
    out.close();
    fileOut.close();
  }

  private static <T> T deserializer(String path) throws IOException, ClassNotFoundException {
    FileInputStream fileIn = new FileInputStream(path);
    ObjectInputStream in = new ObjectInputStream(fileIn);

    T container = (T) in.readObject();

    in.close();
    fileIn.close();

    return container;
  }

  /**
   * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
   * the list of registered security Providers, starting with the most preferred Provider is traversed.
   *
   * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
   * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
   * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
   *
   * @param javaSignatureAlgorithm signature algorithm under JAVA form.
   * @param privateKey             private key to use
   * @param bytes                  the data to digest
   * @return digested and encrypted array of bytes
   */
  @Deprecated
  public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final byte[] bytes) {
    try {
      java.security.Signature signature = java.security.Signature.getInstance(javaSignatureAlgorithm);
      signature.initSign(privateKey);
      signature.update(bytes);
      final byte[] signatureValue = signature.sign();
      return signatureValue;
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

}
