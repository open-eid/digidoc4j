package org.digidoc4j.impl.asic.ocsp;

import java.security.SecureRandom;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class BDocTSOcspSource extends SKOnlineOCSPSource {

  private static final Logger logger = LoggerFactory.getLogger(BDocTSOcspSource.class);

  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
    logger.debug("Using TS OCSP source");
  }

  @Override
  public Extension createNonce() {
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
