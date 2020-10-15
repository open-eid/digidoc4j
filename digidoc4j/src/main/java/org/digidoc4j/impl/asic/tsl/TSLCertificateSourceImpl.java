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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Certificate source with the purpose of adding trusted certificate(s) manually
 * <p/>
 * PS! When then adding CA/QC certificates manually,
 * note that service info's country code of the certificate
 * must match with at least one of the TLInfo's country code. <br/>
 * TlInfo(s) can be added with {@link #updateTlInfo(String, TLInfo)}
 */
public class TSLCertificateSourceImpl extends TrustedListsCertificateSource implements TSLCertificateSource {

  public static final String OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";

  private static final Logger logger = LoggerFactory.getLogger(TSLCertificateSourceImpl.class);

  public TSLCertificateSourceImpl() {
  }

  /**
   * Add a certificate to the TSL
   * <p/>
   * ServiceName will be the certificate's CN field value <br/>
   * ServiceTypeIdentifier will be: <br/>
   * http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC - if certificate contains "OCSPSigning" extended key usage <br/>
   * http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST - if certificate contains "timeStamping" extended key usage
   * http://uri.etsi.org/TrstSvc/Svctype/CA/QC - otherwise <br/>
   * Qualifier will be http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD with nonRepudiation <br/>
   * ServiceStatus will be: <br/>
   * Certificate's NotBefore pre Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision <br/>
   * Certificate's NotBefore post Eidas -> http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted <br/>
   * CountryCode will be EU <br/>
   * TLInfo for EU will be added automatically when it does not exist
   *
   * @param certificate X509 certificate to be added to the list
   */
  @Override
  public void addTSLCertificate(X509Certificate certificate) {
    TrustServiceProviderBuilder trustServiceProviderBuilder = new TrustServiceProviderBuilder();
    trustServiceProviderBuilder.setTerritory("EU");
    trustServiceProviderBuilder.setNames(new HashMap<String, List<String>>() {{
      put("EN", Collections.singletonList(getCN(certificate)));
    }});

    TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder extensionsBuilder = new TrustServiceStatusAndInformationExtensions.
            TrustServiceStatusAndInformationExtensionsBuilder();
    extensionsBuilder.setNames(new HashMap<String, List<String>>() {{
      put("EN", Collections.singletonList(getCN(certificate)));
    }});
    extensionsBuilder.setType(getServiceType(certificate));
    extensionsBuilder.setStatus(getStatus(certificate.getNotBefore()));
    extensionsBuilder.setConditionsForQualifiers(Collections.emptyList());
    extensionsBuilder.setAdditionalServiceInfoUris(Collections.emptyList());
    extensionsBuilder.setServiceSupplyPoints(Collections.emptyList());
    extensionsBuilder.setExpiredCertsRevocationInfo(null);
    extensionsBuilder.setStartDate(new Date());
    extensionsBuilder.setEndDate(new Date());
    TrustServiceStatusAndInformationExtensions statusAndInformationExtensions = extensionsBuilder.build();

    MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<>();
    statusHistoryList.addOldest(statusAndInformationExtensions);

    TLInfo tlInfo = new TLInfo(null, null, null, "EU.xml");
    TrustProperties trustProperties = new TrustProperties(tlInfo.getIdentifier(), trustServiceProviderBuilder.build(), statusHistoryList);
    super.addCertificate(new CertificateToken(certificate), Collections.singletonList(trustProperties));
  }

  /**
   * Invalidates cache
   * <p>
   * Only applicable when cache is used.
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
    X500Name x500name = new X500Name(certificate.getSubjectX500Principal().getName());
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
