package org.digidoc4j.impl.asic;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocValidationReportBuilder;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;

import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SimpleReport;

/**
 * Created by Andrei on 27.11.2017.
 */
public class TimeStampValidationResult implements ValidationResult {
  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<DigiDoc4JException> containerErrorsOnly = new ArrayList<>();
  private BDocValidationReportBuilder reportBuilder;
  private List<SimpleReport> simpleReports = new ArrayList<>();
  private String signedBy = "";
  private String signedTime = "";
  private TimeStampToken timeStampToken;

  /**
   * Get TimeStamp Token.
   */
  public TimeStampToken getTimeStampToken() {
    return timeStampToken;
  }

  /**
   * Set TimeStamp Token.
   *
   * @param timeStampToken
   */
  public void setTimeStampToken(TimeStampToken timeStampToken) {
    this.timeStampToken = timeStampToken;
  }

  /**
   * Get signed time.
   */
  public String getSignedTime() {
    return signedTime;
  }

  /**
   * Set signed time.
   *
   * @param signedTime
   */
  public void setSignedTime(String signedTime) {
    this.signedTime = signedTime;
  }

  /**
   * Get signed by value.
   */
  public String getSignedBy() {
    return signedBy;
  }

  /**
   * Set signed by value.
   *
   * @param signedBy
   */
  public void setSignedBy(String signedBy) {
    this.signedBy = signedBy;
  }

  @Override
  public List<DigiDoc4JException> getErrors() {
    return null;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    throw new NotSupportedException("Not Supported in case of timestamp token");
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
  public boolean hasErrors() {
    return !errors.isEmpty();
  }

  @Override
  public boolean hasWarnings() {
    return false;
  }

  @Override
  public boolean isValid() {
    return !hasErrors();
  }

  @Override
  public String getReport() {
    return null;
  }

  @Override
  public List<SignatureValidationReport> getSignatureReports() {
    throw new NotSupportedException("Not Supported in case of timestamp token");
  }

  @Override
  public List<SimpleReport> getSignatureSimpleReports() {
    throw new NotYetImplementedException();
  }

  @Override
  @Deprecated
  public Indication getIndication(String signatureId) {
    throw new NotSupportedException("Not supported in case of timestamp token container");
  }

  /**
   * Gets container indication (TOTAL_PASSED or TOTAL_FAILED)
   *
   * @return Indication
   */
  public Indication getIndication() {
    if (!hasErrors()) {
      return Indication.TOTAL_PASSED;
    }
    return Indication.TOTAL_FAILED;
  }

  @Override
  @Deprecated
  public SubIndication getSubIndication(String signatureId) {
    throw new NotSupportedException("Not Supported in case of timestamp token");
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    throw new NotSupportedException("Not Supported in case of timestamp token");
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    throw new NotYetImplementedException();
  }

  @Override
  public void saveXmlReports(Path directory) {
    throw new NotYetImplementedException();
  }
}
