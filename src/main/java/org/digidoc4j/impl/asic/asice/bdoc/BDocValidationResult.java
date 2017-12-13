/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice.bdoc;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;

import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SimpleReport;

/**
 * Validation result information.
 *
 * For BDOC the ValidationResult contains only information for the first signature of each signature XML file
 */
public class BDocValidationResult implements ValidationResult {

  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<DigiDoc4JException> containerErrorsOnly = new ArrayList<>();
  private BDocValidationReportBuilder reportBuilder;
  private List<SimpleReport> simpleReports = new ArrayList<>();

  @Override
  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  @Override
  @Deprecated
  public boolean hasErrors() {
    return !errors.isEmpty();
  }

  @Override
  public boolean hasWarnings() {
    return !warnings.isEmpty();
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }

  @Override
  public String getReport() {
    return reportBuilder.buildXmlReport();
  }

  @Override
  public List<SignatureValidationReport> getSignatureReports() {
    return reportBuilder.buildSignatureValidationReports();
  }

  @Override
  public List<SimpleReport> getSignatureSimpleReports() {
    return buildSignatureSimpleReports();
  }

  private List<SimpleReport> buildSignatureSimpleReports() {
    if (simpleReports.isEmpty()){
      simpleReports = reportBuilder.buildSignatureSimpleReports();
    }
    return simpleReports;
  }

  @Override
  public Indication getIndication(String signatureId){
    if (StringUtils.isBlank(signatureId)){
      SimpleReport simpleReport = getSimpleReport();
      return simpleReport != null ? simpleReport.getIndication(simpleReport.getFirstSignatureId()) : null;
    }
    SimpleReport reportBySignatureId = getSimpleReportBySignatureId(signatureId);
    return reportBySignatureId != null ? reportBySignatureId.getIndication(signatureId) : null;
  }

  @Override
  public SubIndication getSubIndication(String signatureId){
    if (StringUtils.isBlank(signatureId)){
      SimpleReport simpleReport = getSimpleReport();
      return  simpleReport != null ? simpleReport.getSubIndication(simpleReport.getFirstSignatureId()) : null;
    }
    SimpleReport reportBySignatureId = getSimpleReportBySignatureId(signatureId);
    return reportBySignatureId != null ? reportBySignatureId.getSubIndication(signatureId) : null;
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId){
    if (StringUtils.isBlank(signatureId)){
      SimpleReport simpleReport = getSimpleReport();
      return simpleReport != null ? simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()) : null;
    }
    SimpleReport reportBySignatureId = getSimpleReportBySignatureId(signatureId);
    return reportBySignatureId != null ? reportBySignatureId.getSignatureQualification(signatureId) : null;
  }

  private SimpleReport getSimpleReport() {
    if (buildSignatureSimpleReports().size() > 0){
      return buildSignatureSimpleReports().get(0);
    }
    return null;
  }

  private SimpleReport getSimpleReportBySignatureId(String signatureId) {
      for (SimpleReport signatureReport: buildSignatureSimpleReports()) {
        if (signatureReport.getFirstSignatureId().equals(signatureId)){
          return signatureReport;
        }
      }
    return null;
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerErrorsOnly;
  }

  /**
   * Save DSS validation reports in given directory.
   *
   * @param directory Directory where to save XML files. When null then do nothing.
   */
  @Override
  public void saveXmlReports(Path directory) {
    if (directory != null) {
      reportBuilder.saveXmlReports(directory);
    }
  }

  /**
   * Set container errors only.
   *
   * @param containerErrorsOnly
   */
  public void setContainerErrorsOnly(List<DigiDoc4JException> containerErrorsOnly) {
    this.containerErrorsOnly = containerErrorsOnly;
  }

  /**
   * Set Errors.
   *
   * @param errors
   */
  public void setErrors(List<DigiDoc4JException> errors) {
    this.errors = errors;
  }

  /**
   * Set warnings.
   *
   * @param warnings
   */
  public void setWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = warnings;
  }

  /**
   * Set report builder.
   *
   * @param reportBuilder
   */
  public void setReportBuilder(BDocValidationReportBuilder reportBuilder) {
    this.reportBuilder = reportBuilder;
  }
}
