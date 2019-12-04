package org.digidoc4j;

import java.security.cert.X509Certificate;

import org.digidoc4j.exceptions.CertificateValidationException;

import eu.europa.esig.dss.spi.x509.CertificateSource;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public interface CertificateValidator {

  /**
   * Calls validation logic for given certificate
   *
   * @param subjectCertificate subject certificate to validate
   * @throws CertificateValidationException exception containing validation status
   */
  void validate(X509Certificate subjectCertificate) throws CertificateValidationException;

  /**
   * @return CertificateSource
   */
  CertificateSource getCertificateSource();

}
