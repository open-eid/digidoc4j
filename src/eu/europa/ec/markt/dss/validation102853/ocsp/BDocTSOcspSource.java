package eu.europa.ec.markt.dss.validation102853.ocsp;

import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.digidoc4j.Configuration;

public class BDocTSOcspSource extends SKOnlineOCSPSource{
  public BDocTSOcspSource(Configuration configuration) {
    super(configuration);
  }

  @Override
  void addNonce(OCSPReqBuilder ocspReqBuilder) {

  }
}
