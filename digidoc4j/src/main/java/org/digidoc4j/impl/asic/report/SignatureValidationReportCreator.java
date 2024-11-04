/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.report;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlToken;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class SignatureValidationReportCreator extends TokenValidationReportCreator {

  private static final Logger log = LoggerFactory.getLogger(SignatureValidationReportCreator.class);

  private final SignatureValidationData validationData;
  private SignatureValidationReport signatureValidationReport;

  public SignatureValidationReportCreator(SignatureValidationData validationData) {
    super(validationData.getReport().getReports());
    this.validationData = validationData;
  }

  public static SignatureValidationReport create(SignatureValidationData validationData) {
    return new SignatureValidationReportCreator(validationData).createSignatureValidationReport();
  }

  private SignatureValidationReport createSignatureValidationReport() {
    signatureValidationReport = cloneSignatureValidationReport();
    updateMissingErrorsAndWarnings(validationData.getValidationResult(), signatureValidationReport);
    updateDocumentName();
    updateIndication();
    updateSignatureFormat();
    updateSignatureId();
    updateSignedBy();
    return signatureValidationReport;
  }

  private SignatureValidationReport cloneSignatureValidationReport() {
    if (simpleReport.getSignaturesCount() > 1) {
      log.warn("Simple report contains more than one signature: {}", simpleReport.getSignaturesCount());
    }
    Optional<XmlToken> signatureXmlReport = simpleReport.getSignatureOrTimestampOrEvidenceRecord().stream()
            .filter(s -> s instanceof XmlSignature)
            .findFirst();
    if (signatureXmlReport.isPresent()) {
      return SignatureValidationReport.create((XmlSignature) signatureXmlReport.get());
    }
    throw new IllegalArgumentException("No signature found from simple report");
  }

  private void updateDocumentName() {
    String documentName = reports.getDiagnosticData().getDocumentName();
    signatureValidationReport.setDocumentName(documentName);
  }

  private void updateIndication() {
    if (!validationData.getValidationResult().isValid() && (signatureValidationReport.getIndication() == Indication.TOTAL_PASSED || signatureValidationReport.getIndication() == Indication.PASSED)) {
      signatureValidationReport.setIndication(Indication.INDETERMINATE);
    }
  }

  private void updateSignatureFormat() {
    if (validationData.getSignatureProfile() == SignatureProfile.LT_TM) {
      signatureValidationReport.setSignatureFormat(SignatureLevel.XAdES_BASELINE_LT_TM);
    }
    if (validationData.getSignatureProfile() == SignatureProfile.B_EPES) {
      signatureValidationReport.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B_EPES);
    }
  }

  private void updateSignatureId() {
    signatureValidationReport.setId(validationData.getSignatureId());
  }

  private void updateSignedBy() {
    final String signedBy = signatureValidationReport.getSignedBy();
    if (signedBy != null && signatureValidationReport.getCertificateChain() != null) {
      signatureValidationReport.getCertificateChain().getCertificate().stream()
              .filter(c -> signedBy.equals(c.getId()))
              .map(XmlCertificate::getQualifiedName)
              .findFirst()
              .ifPresent(signatureValidationReport::setSignedBy);
    }
  }
}
