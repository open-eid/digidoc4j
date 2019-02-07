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
import java.util.*;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
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
   * ServiceName is the certificate's CN field value<br/>
   * ServiceTypeIdentifier is http://uri.etsi.org/TrstSvc/Svctype/CA/QC <br/>
   * Qualifier is http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   * ServiceStatus is: <br/>
   *    Certificate's NotBefore pre Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   *    Certificate's NotBefore post Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted <br/>
   * CountryCode is EU <br/>
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
    ServiceInfoStatus status = new ServiceInfoStatus(getCN(certificate),"http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
        getStatus(certificate.getNotBefore()),
        qualifiersAndConditions,
            Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"),
        null,
        null,
        certificate.getNotBefore(),
        null);
    TimeDependentValues timeDependentValues = new TimeDependentValues(Arrays.asList(status));
    serviceInfo.setStatus(timeDependentValues);
    serviceInfo.setTlCountryCode("EU");
    addCertificate(new CertificateToken(certificate), Collections.singletonList(serviceInfo));
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

  private String getCN(X509Certificate certificate) {
    X500Name x500name = new X500Name(certificate.getSubjectX500Principal().getName() );
    RDN cn = x500name.getRDNs(BCStyle.CN)[0];
    return IETFUtils.valueToString(cn.getFirst().getValue());
  }

  private String getStatus(Date startDate) {
    if (EIDASUtils.isPostEIDAS(startDate)) {
      return "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    } else {
      return "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";
    }
  }

}
