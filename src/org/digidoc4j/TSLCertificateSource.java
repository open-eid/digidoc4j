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

import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * Trusted List certificates
 */
public class TSLCertificateSource extends TrustedListsCertificateSource {
  private static final Logger logger = LoggerFactory.getLogger(TSLCertificateSource.class);
  protected static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");

  /**
   * Add a certificate to the TSL
   * <p/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC
   * ServiceStatus is http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision
   *
   * @param certificate X509 certificate to be added to the list
   */
  public void addTSLCertificate(X509Certificate certificate) {
    logger.debug("");
    ServiceInfo serviceInfo = new ServiceInfo();
    serviceInfo.setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");
    serviceInfo.setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
    serviceInfo.setStatusStartDate(certificate.getNotBefore());

    addCertificate(certificate, serviceInfo);
  }

  /**
   * Invalidates cache and reloads TSL.
   *
   * Only applicable when cache is used.
   *
   */
  public void invalidateCache() {
    logger.debug("");
    if (dataLoader instanceof FileCacheDataLoader) {
      try {
        FileUtils.cleanDirectory(fileCacheDirectory);
      } catch (Exception e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e);
      }
      init();
    }
  }
}
