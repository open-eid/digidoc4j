package prototype;

import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.Signer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * This signer implementation is for testing purposes
 */
@Deprecated
public class PKCS11Signer implements Signer {
  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;


  /**
   * Constructor
   *
   * @param password password
   */
  public PKCS11Signer(char[] password) {
    Configuration configuration = new Configuration();
    signatureTokenConnection = new Pkcs11SignatureToken(configuration.getPKCS11ModulePath(), password, 2);
    keyEntry = signatureTokenConnection.getKeys().get(0);
  }

  @Override
  public X509Certificate getCertificate() {
    return keyEntry.getCertificate();
  }

  @Override
  public PrivateKey getPrivateKey() {
    return keyEntry.getPrivateKey();
  }

  @Override
  public byte[] sign(Container container, byte[] dataToSign) {
    return new byte[0];
  }
}
