package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.security.SecureRandom;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.Configuration;


public class BDocTSOcspSource extends SKOnlineOCSPSource{
  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  Extension createNonce() {
    byte[] bytes = generateRandomNonce();
    DEROctetString nonce = new DEROctetString(bytes);
    boolean critical = false;
    return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, critical, nonce);
  }

  private byte[] generateRandomNonce() {
    SecureRandom random = new SecureRandom();
    byte[] nonceBytes = new byte[20];
    random.nextBytes(nonceBytes);
    return nonceBytes;
  }
}
