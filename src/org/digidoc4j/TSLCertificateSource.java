/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.File;
import java.security.cert.X509Certificate;

import org.digidoc4j.impl.bdoc.TslLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Trusted List certificates
 */
public class TSLCertificateSource extends TrustedListsCertificateSource {
  private static final Logger logger = LoggerFactory.getLogger(TSLCertificateSource.class);
  protected static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");
  private TslLoader tslLoader;

  public TSLCertificateSource() {
  }

  public TSLCertificateSource(TslLoader tslLoader) {
    this.tslLoader = tslLoader;
  }

  /**
   * Add a certificate to the TSL
   * <p/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC
   * ServiceStatus is http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision
   *
   * @param certificate X509 certificate to be added to the list
   */
  public void addTSLCertificate(X509Certificate certificate) {
    ServiceInfo serviceInfo = new ServiceInfo();
    serviceInfo.setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");
    serviceInfo.setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    serviceInfo.setStatusStartDate(certificate.getNotBefore());

    addCertificate(new CertificateToken(certificate), serviceInfo);
  }

  /**
   * Invalidates cache and reloads TSL.
   *
   * Only applicable when cache is used.
   *
   */
  public void invalidateCache() {
    logger.debug("Invalidating TSL cache");
    if(tslLoader != null) {
      tslLoader.invalidateCache();
      tslLoader.refresh();
    } else {
      logger.warn("TSL Loader is null, skipping TSL cache invalidation");
    }
  }


}
