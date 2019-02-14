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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

import eu.europa.esig.dss.tsl.*;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.util.TimeDependentValues;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Certificate source with the purpose of adding trusted certificate(s) manually
 * <p/>
 * PS! When then adding CA/QC certificates manually,
 * note that service info's country code of the certificate
 * must match with at least one of the TLInfo's country code. <br/>
 * TlInfo(s) can be added with {@link #updateTlInfo(String, TLInfo)}
 */
public class TSLCertificateSourceImpl extends TrustedListsCertificateSource implements TSLCertificateSource {

  public static String OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";

  private static final Logger logger = LoggerFactory.getLogger(TSLCertificateSourceImpl.class);

  public TSLCertificateSourceImpl() {
  }

  /**
   * Add a certificate to the TSL
   * <p/>
   * ServiceName will be the certificate's CN field value <br/>
   * ServiceTypeIdentifier will be: <br/>
   *    http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC - if certificate contains "OCSPSigning" extended key usage <br/>
   *    http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST - if certificate contains "timeStamping" extended key usage
   *    http://uri.etsi.org/TrstSvc/Svctype/CA/QC - otherwise <br/>
   * Qualifier will be http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   * ServiceStatus will be: <br/>
   *    Certificate's NotBefore pre Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   *    Certificate's NotBefore post Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted <br/>
   * CountryCode will be EU <br/>
   * TLInfo for EU will be added automatically when it does not exist
   *
   * @param certificate X509 certificate to be added to the list
   */
  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    ServiceInfo serviceInfo = new ServiceInfo();
    Condition condition = new KeyUsageCondition(KeyUsageBit.nonRepudiation, true);
    Map<String, List<Condition>> qualifiersAndConditions = new HashMap<>();
    qualifiersAndConditions.put("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD", Arrays.asList(condition));
    ServiceInfoStatus status = new ServiceInfoStatus(getCN(certificate), getServiceType(certificate),
        getStatus(certificate.getNotBefore()),
        qualifiersAndConditions,
            Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"),
        null,
        null,
        certificate.getNotBefore(),
        null);
    TimeDependentValues timeDependentValues = new TimeDependentValues(Arrays.asList(status));
    serviceInfo.setStatus(timeDependentValues);

    String countryCode = "EU";
    serviceInfo.setTlCountryCode(countryCode);
    if (getTlInfo(countryCode) == null) {
      TLInfo tlInfo = new TLInfo();
      tlInfo.setCountryCode(countryCode);
      tlInfo.setVersion(5);
      updateTlInfo(countryCode, tlInfo);
    }
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

  private String getServiceType(X509Certificate certificate) {
    try {
      List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
      if (extendedKeyUsage != null) {
        if (extendedKeyUsage.contains(SKOnlineOCSPSource.OID_OCSP_SIGNING)) {
          return "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC";
        }
        if (extendedKeyUsage.contains(OID_TIMESTAMPING)) {
          return "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
        }
      }
    } catch (CertificateParsingException e) {
      logger.warn("Error decoding extended key usage from certificate <{}>", certificate.getSubjectDN().getName());
    }
    return "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
  }

  private String getStatus(Date startDate) {
    if (EIDASUtils.isPostEIDAS(startDate)) {
      return "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    } else {
      return "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";
    }
  }

}
