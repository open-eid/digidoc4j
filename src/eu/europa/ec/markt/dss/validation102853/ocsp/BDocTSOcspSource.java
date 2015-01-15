package eu.europa.ec.markt.dss.validation102853.ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.digidoc4j.Configuration;

import java.security.SecureRandom;

public class BDocTSOcspSource extends SKOnlineOCSPSource{
  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  void addNonce(OCSPReqBuilder ocspReqBuilder) {
    SecureRandom random = new SecureRandom();

    this.nonce = new DEROctetString(random.generateSeed(20));
    final Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, this.nonce);
    final Extensions extensions = new Extensions(extension);
    ocspReqBuilder.setRequestExtensions(extensions);
  }
}
