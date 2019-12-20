package org.digidoc4j.impl;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public abstract class AbstractSignatureValidationResult extends AbstractValidationResult implements
    SignatureValidationResult {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractSignatureValidationResult.class);
  protected List<SignatureValidationReport> reports = new ArrayList<>();
  protected List<SimpleReport> simpleReports = new ArrayList<>();
  protected String report;

  /*
   * ACCESSORS
   */

  @Override
  public List<SignatureValidationReport> getReports() { //TODO ASIC specific
    return this.reports;
  }

  @Override
  public Indication getIndication(String signatureId) {
    LOGGER.info(this.getNotSupportedMessage());
    return null;
  }

  @Override
  public SubIndication getSubIndication(String signatureId) {
    LOGGER.info(this.getNotSupportedMessage());
    return null;
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    LOGGER.info(this.getNotSupportedMessage());
    return null;
  }

  @Override
  public void saveXmlReports(Path directory) {
    LOGGER.info(this.getNotSupportedMessage());
  }

  /*
   * RESTRICTED METHODS
   */

  protected String getNotSupportedMessage() {
    return String.format("Not supported for <%s>", this.getResultName());
  }

  /*
   * ACCESSORS
   */

  @Override
  public List<SimpleReport> getSimpleReports() {
    return this.simpleReports;
  }

  @Override
  public String getReport() {
    return report;
  }

  public void setReport(String report) {
    this.report = report;
  }

}
