/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.tsl;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.digidoc4j.TSLCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.tsl.KeyUsageCondition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.util.TimeDependentValues;
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
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC <br/>
   * ServiceStatus is http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   * Qualifier is http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   *
   * @param certificate X509 certificate to be added to the list
   */
  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    ServiceInfo serviceInfo = new ServiceInfo();
    //TODO test addTSLCertificate
    Condition condition = new KeyUsageCondition(KeyUsageBit.nonRepudiation, true);
    Map<String, List<Condition>> qualifiersAndConditions = new HashMap<String, List<Condition>>();
    qualifiersAndConditions.put("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD", Arrays.asList(condition));
    ServiceInfoStatus status = new ServiceInfoStatus("http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
        qualifiersAndConditions,
        null,
        null,
        null,
        certificate.getNotBefore(),
        null);
    TimeDependentValues timeDependentValues = new TimeDependentValues(Arrays.asList(status));
    serviceInfo.setStatus(timeDependentValues);
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
