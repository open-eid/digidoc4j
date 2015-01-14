package eu.europa.ec.markt.dss.validation102853.ocsp;

import eu.europa.ec.markt.dss.DSSUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.digidoc4j.Configuration;

public class BDocTSOcspSource extends SKOnlineOCSPSource{
  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  void addNonce(OCSPReqBuilder ocspReqBuilder) {
    final long currentTimeNonce = System.currentTimeMillis();

    nonce = new DEROctetString(DSSUtils.toByteArray(currentTimeNonce));
    final Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
    final Extensions extensions = new Extensions(extension);
    ocspReqBuilder.setRequestExtensions(extensions);
  }
}
