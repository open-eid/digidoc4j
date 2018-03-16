package org.digidoc4j.impl;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.Configuration;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class CommonOCSPSource extends SKOnlineOCSPSource {

  private final Logger log = LoggerFactory.getLogger(CommonOCSPSource.class);

  /**
   * @param configuration configuration
   */
  public CommonOCSPSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  public Extension createNonce() {
    this.log.debug("Creating default OCSP nonce ...");
    return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(Helper
        .generateRandomBytes(32)));
  }

}
