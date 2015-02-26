package eu.europa.ec.markt.dss.validation102853.ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.digidoc4j.Configuration;

import eu.europa.ec.markt.dss.DSSUtils;

public class BDocTSOcspSource extends SKOnlineOCSPSource{
  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  Extension createNonce() {
    final long currentTimeNonce = System.currentTimeMillis();

    DEROctetString nonce = new DEROctetString(DSSUtils.toByteArray(currentTimeNonce));
    return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
  }
}
