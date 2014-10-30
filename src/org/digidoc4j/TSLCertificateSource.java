package org.digidoc4j;

import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;

import java.security.cert.X509Certificate;

/**
 * Trusted List certificates
 */
public class TSLCertificateSource extends TrustedListsCertificateSource {

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

    addCertificate(certificate, serviceInfo);
  }
}
