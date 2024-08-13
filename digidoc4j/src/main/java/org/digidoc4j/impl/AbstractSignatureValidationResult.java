/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public abstract class AbstractSignatureValidationResult extends AbstractValidationResult implements
    SignatureValidationResult {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractSignatureValidationResult.class);
  protected List<SignatureValidationReport> signatureReports = new ArrayList<>();
  protected List<SimpleReport> simpleReports = new ArrayList<>();
  protected String report;

  /*
   * ACCESSORS
   */

  @Override
  public List<SignatureValidationReport> getSignatureReports() { //TODO ASIC specific
    return signatureReports;
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
