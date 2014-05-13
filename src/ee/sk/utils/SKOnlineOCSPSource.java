package ee.sk.utils;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ocsp.OnlineOCSPSource;

import java.security.cert.X509Certificate;

public class SKOnlineOCSPSource extends OnlineOCSPSource {
  @Override
  public String getAccessLocation(X509Certificate certificate) throws DSSException {
    return "http://www.openxades.org/cgi-bin/ocsp.cgi";
    //return "http://ocsp.sk.ee";
  }
}
