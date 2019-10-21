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

import java.util.List;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.xades.validation.SignatureValidationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.validation.reports.Reports;

public class SignatureValidationReportCreator {

  private final static Logger logger = LoggerFactory.getLogger(SignatureValidationReportCreator.class);
  private SignatureValidationData validationData;
  private Reports reports;
  private XmlSimpleReport simpleReport;
  private SignatureValidationReport signatureValidationReport;

  public SignatureValidationReportCreator(SignatureValidationData validationData) {
    this.validationData = validationData;
    this.reports = validationData.getReport().getReports();
    this.simpleReport = reports.getSimpleReportJaxb();
  }

  public static SignatureValidationReport create(SignatureValidationData validationData) {
    return new SignatureValidationReportCreator(validationData).createSignatureValidationReport();
  }

  private SignatureValidationReport createSignatureValidationReport() {
    signatureValidationReport = cloneSignatureValidationReport();
    updateMissingErrors();
    updateDocumentName();
    updateIndication();
    updateSignatureFormat();
    return signatureValidationReport;
  }

  private SignatureValidationReport cloneSignatureValidationReport() {
    if (simpleReport.getSignature().size() > 1) {
      logger.warn("Simple report contains more than one signature: " + simpleReport.getSignature().size());
    }
    XmlSignature signatureXmlReport = simpleReport.getSignature().get(0);
    return SignatureValidationReport.create(signatureXmlReport);
  }

  private void updateMissingErrors() {
    List<String> errors = signatureValidationReport.getErrors();
    for (DigiDoc4JException error : validationData.getValidationResult().getErrors()) {
      if (!errors.contains(error.getMessage())) {
        errors.add(error.getMessage());
      }
    }
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
}
