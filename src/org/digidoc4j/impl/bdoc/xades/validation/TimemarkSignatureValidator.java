/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades.validation;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.SignedWithExpiredCertificateException;
import org.digidoc4j.exceptions.UntrustedRevocationSourceException;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public class TimemarkSignatureValidator extends XadesSignatureValidator {

  private final static Logger logger = LoggerFactory.getLogger(TimemarkSignatureValidator.class);
  private XadesSignature signature;

  public TimemarkSignatureValidator(XadesSignature signature) {
    super(signature);
    this.signature = signature;
  }

  @Override
  protected void populateValidationErrors() {
    super.populateValidationErrors();
    addCertificateExpirationError();
    addRevocationErrors();
  }

  private void addCertificateExpirationError() {
    Date signingTime = signature.getTrustedSigningTime();
    if (signingTime == null) {
      return;
    }
    X509Certificate signerCert = signature.getSigningCertificate().getX509Certificate();
    Date notBefore = signerCert.getNotBefore();
    Date notAfter = signerCert.getNotAfter();
    boolean isCertValid = signingTime.compareTo(notBefore) >= 0 && signingTime.compareTo(notAfter) <= 0;
    if (!isCertValid) {
      logger.error("Signature has been created with expired certificate");
      addValidationError(new SignedWithExpiredCertificateException());
    }
  }

  private void addRevocationErrors() {
    Reports validationReport = signature.validate().getReport();
    DiagnosticData diagnosticData = validationReport.getDiagnosticData();
    if (diagnosticData == null) {
      return;
    }
    String signingCertificateId = diagnosticData.getSigningCertificateId();
    String certificateRevocationSource = diagnosticData.getCertificateRevocationSource(signingCertificateId);
    logger.debug("Revocation source is " + certificateRevocationSource);
    if (StringUtils.equalsIgnoreCase("CRLToken", certificateRevocationSource)) {
      logger.error("Signing certificate revocation source is CRL instead of OCSP");
      addValidationError(new UntrustedRevocationSourceException());
    }
  }
}
