package prototype.samples;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.token.Constants;
import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.Container;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.ExternalSigner;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class AsyncSigning {

  public static void main(String[] args) throws IOException, ClassNotFoundException {
    System.setProperty("digidoc4j.mode", "TEST");

    Container container = Container.create();
    container.addDataFile("testFiles/test.txt", "text/plain");


    X509Certificate signerCert = getSignerCert();

    SignedInfo signedInfo = container.prepareSigning(signerCert);

    serialize(container);

    //getSignature
    byte[] signature = getExternalSignature(container, signerCert, signedInfo);



    Container deserializedContainer = deserializer();
    deserializedContainer.signRaw(signature);
    deserializedContainer.save("deserializedContainer.bdoc");

    //serialize container
    serialize(deserializedContainer);
  }

  private static byte[] getExternalSignature(Container container, final X509Certificate signerCert, SignedInfo prepareSigningSignature) {
    Signer externalSigner = new ExternalSigner(signerCert) {
      @Override
      public byte[] sign(Container container, byte[] dataToSign) {
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
        return ArrayUtils.addAll(Constants.SHA256_DIGEST_INFO_PREFIX, digest);
      }

    };

    return externalSigner.sign(container, prepareSigningSignature.getDigest());
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

  private static void serialize(Container container) throws IOException {

    FileOutputStream fileOut = new FileOutputStream("container.bin");
    ObjectOutputStream out = new ObjectOutputStream(fileOut);
    out.writeObject(container);
    out.flush();
    out.close();
    fileOut.close();
  }

  private static Container deserializer() throws IOException, ClassNotFoundException {
    FileInputStream fileIn = new FileInputStream("container.bin");
    ObjectInputStream in = new ObjectInputStream(fileIn);

    Container container = (Container) in.readObject();

    in.close();
    fileIn.close();

    return container;
  }

}
