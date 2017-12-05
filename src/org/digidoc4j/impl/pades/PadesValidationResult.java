package org.digidoc4j.impl.pades;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.report.SignatureValidationReport;

import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SimpleReport;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesValidationResult implements ValidationResult {

  private String report;
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<SimpleReport> simpleReports = new ArrayList<>();

  public PadesValidationResult(SimpleReport simpleReport) {
    this.simpleReports = Arrays.asList(simpleReport);
  }

  @Override
  public boolean hasErrors() {
    return !getErrors().isEmpty();
  }

  @Override
  public boolean hasWarnings() {
    return !getWarnings().isEmpty();
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

  @Override
  public boolean isValid() {
    return !hasErrors();
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  @Override
  public String getReport() {
    return report;
  }

  /**
   * Set report.
   *
   * @param report
   */
  public void setReport(String report){
    this.report = report;
  }

  @Override
  public List<SignatureValidationReport> getSignatureReports() {
    return null;
  }

  @Override
  public List<SimpleReport> getSignatureSimpleReports() {
    return simpleReports;
  }

  @Override
  public Indication getIndication(String signatureId) {
    if (StringUtils.isNotBlank(signatureId)){
      return simpleReports.get(0).getIndication(signatureId);
    }
    throw new DigiDoc4JException("Signature id must be not null");
  }

  @Override
  public SubIndication getSubIndication(String signatureId) {
    if (StringUtils.isNotBlank(signatureId)){
      return simpleReports.get(0).getSubIndication(signatureId);
    }
    throw new DigiDoc4JException("Signature id must be not null");
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    return null;
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return null;
  }

  @Override
  public void saveXmlReports(Path directory) {

  }
}
