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

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.condition.KeyUsageCondition;
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
import java.util.Optional;

/**
 * Certificate source with the purpose of adding trusted certificate(s) manually
 * <p/>
 */
public class TSLCertificateSourceImpl extends TrustedListsCertificateSource implements TSLCertificateSource {

  public static final String OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
  public static final String FOR_ESIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";
  private static final String CUSTOM_LOTL_URL = "user_defined_LOTL";
  private static final String CUSTOM_TL_URL = "user_defined_TL";


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
   *
   * @param certificate X509 certificate to be added to the list
   */
  @Override
  public void addTSLCertificate(X509Certificate certificate) {

    TrustServiceProviderBuilder trustServiceProviderBuilder = new TrustServiceProviderBuilder();
    trustServiceProviderBuilder.setTerritory("EU");
    trustServiceProviderBuilder.setNames(new HashMap<String, List<String>>() {{
      put("EN", Arrays.asList(getCN(certificate)));
    }});

    TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder extensionsBuilder = new TrustServiceStatusAndInformationExtensions.
            TrustServiceStatusAndInformationExtensionsBuilder();
    extensionsBuilder.setNames(new HashMap<String, List<String>>() {{
      put("EN", Arrays.asList(getCN(certificate)));
    }});

    extensionsBuilder.setType(getServiceType(certificate));
    extensionsBuilder.setStatus(getStatus(certificate.getNotBefore()));
    Condition condition = new KeyUsageCondition(KeyUsageBit.NON_REPUDIATION, true);

    ConditionForQualifiers conditionForQualifiers = new ConditionForQualifiers(condition, Arrays.asList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"));
    extensionsBuilder.setConditionsForQualifiers(Arrays.asList(conditionForQualifiers));
    extensionsBuilder.setAdditionalServiceInfoUris(Collections.singletonList(FOR_ESIGNATURES));
    extensionsBuilder.setStartDate(certificate.getNotBefore());
    extensionsBuilder.setEndDate(null);

    TrustServiceStatusAndInformationExtensions statusAndInformationExtensions = extensionsBuilder.build();
    MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<>();
    statusHistoryList.addOldest(statusAndInformationExtensions);

    TrustProperties trustProperties = new TrustProperties(getFirstSuitableTLInfo().getIdentifier(),
            trustServiceProviderBuilder.build(), statusHistoryList);

    addCertificate(new CertificateToken(certificate), Arrays.asList(trustProperties));
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
  public TLValidationJobSummary getSummary() {
    if (super.getSummary() == null) {
      super.setSummary(new TLValidationJobSummary(Arrays.asList(createUserDefinedLOTL()), null));
    }
    return super.getSummary();
  }

  @Override
  public void refresh() {
    logger.warn("Not possible to refresh this certificate source");
  }

  private TLInfo getFirstSuitableTLInfo() {
    Optional<TLInfo> tlInfo = this.getSummary().getLOTLInfos().stream()
            .flatMap(lotlInfo -> lotlInfo.getTLInfos().stream())
            .filter(tl -> CUSTOM_TL_URL.equals(tl.getUrl()))
            .findFirst();
    if (!tlInfo.isPresent()) {
      this.getSummary().getLOTLInfos().add(createUserDefinedLOTL());
    }
    return this.getSummary().getLOTLInfos().get(0).getTLInfos().get(0);
  }

  private LOTLInfo createUserDefinedLOTL() {
    ParsingCacheDTO parsingInfoRecord = new ParsingCacheDTO();
    parsingInfoRecord.setVersion(5);
    TLInfo tlInfo = new TLInfo(null, parsingInfoRecord, null, CUSTOM_TL_URL);
    LOTLInfo lotlInfo = new LOTLInfo(null, parsingInfoRecord, null, CUSTOM_LOTL_URL);
    lotlInfo.setTlInfos(Arrays.asList(tlInfo));
    return lotlInfo;
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
