/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.tsl;

import java.security.cert.X509Certificate;

import org.digidoc4j.TSLCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Trusted List certificates
 */
public class TSLCertificateSourceImpl extends TrustedListsCertificateSource implements TSLCertificateSource {
  private static final Logger logger = LoggerFactory.getLogger(TSLCertificateSourceImpl.class);

  public TSLCertificateSourceImpl() {
  }

  /**
   * Add a certificate to the TSL
   * <p/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC
   * ServiceStatus is http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision
   *
   * @param certificate X509 certificate to be added to the list
   */
  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    ServiceInfo serviceInfo = new ServiceInfo();
    serviceInfo.setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");
    serviceInfo.setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    serviceInfo.setStatusStartDate(certificate.getNotBefore());

    addCertificate(new CertificateToken(certificate), serviceInfo);
  }

  /**
   * Invalidates cache
   *
   * Only applicable when cache is used.
   *
   */
  @Override
  public void invalidateCache() {
    logger.debug("Invalidating TSL cache");
    TslLoader.invalidateCache();
  }

  @Override
  public void refresh() {
    logger.warn("Not possible to refresh this certificate source");
  }

}
