package prototype;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ocsp.OnlineOCSPSource;

import java.security.cert.X509Certificate;

/**
 * SK OCSP source location.
 */
public class SKOnlineOCSPSource extends OnlineOCSPSource {
  @Override
  /**
   * Returns SK OCSP source location.
   *
   * @return OCSP source location
   */
  public String getAccessLocation(X509Certificate certificate) throws DSSException {
    return "http://www.openxades.org/cgi-bin/ocsp.cgi";
    //return "http://ocsp.org.ee";
  }
}
