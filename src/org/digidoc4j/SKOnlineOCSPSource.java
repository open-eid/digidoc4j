package org.digidoc4j;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ocsp.OnlineOCSPSource;
import org.digidoc4j.api.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

/**
 * SK OCSP source location.
 */
public class SKOnlineOCSPSource extends OnlineOCSPSource {
  final Logger logger = LoggerFactory.getLogger(SKOnlineOCSPSource.class);

  @Override
  /**
   * Returns SK OCSP source location.
   *
   * @return OCSP source location
   */
  public String getAccessLocation(X509Certificate certificate) throws DSSException {
    logger.debug("");
    Configuration configuration = new Configuration();
    String location = configuration.getOcspSource();
    logger.debug("OCSP Access location: " + location);
    return configuration.getOcspSource();
  }
}
