/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AbstractSignatureValidationResult;

import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;

/**
 * Validation result information.
 * <p>
 * For BDOC the ValidationResult contains only information for the first signature of each signature XML file
 */
public class AsicContainerValidationResult extends AbstractSignatureValidationResult implements
    ContainerValidationResult {

  private List<DigiDoc4JException> containerErrors = new ArrayList<>();
  private AsicValidationReportBuilder validationReportBuilder;

  @Override
  public Indication getIndication(String signatureId) {
    if (StringUtils.isBlank(signatureId)) {
      SimpleReport report = this.getSimpleReport();
      return report != null ? report.getIndication(report.getFirstSignatureId()) : null;
    }
    SimpleReport report = this.getSimpleReportBySignatureId(signatureId);
    return report != null ? report.getIndication(signatureId) : null;
  }

  @Override
  public SubIndication getSubIndication(String signatureId) {
    if (StringUtils.isBlank(signatureId)) {
      SimpleReport report = this.getSimpleReport();
      return report != null ? report.getSubIndication(report.getFirstSignatureId()) : null;
    }
    SimpleReport report = this.getSimpleReportBySignatureId(signatureId);
    return report != null ? report.getSubIndication(signatureId) : null;
  }

  @Override
  public SignatureQualification getSignatureQualification(String signatureId) {
    if (StringUtils.isBlank(signatureId)) {
      SimpleReport report = this.getSimpleReport();
      return report != null ? report.getSignatureQualification(report.getFirstSignatureId()) : null;
    }
    SimpleReport report = this.getSimpleReportBySignatureId(signatureId);
    return report != null ? report.getSignatureQualification(signatureId) : null;
  }

  /**
   * Save DSS validation reports in given directory.
   *
   * @param directory Directory where to save XML files. When null then do nothing.
   */
  @Override
  public void saveXmlReports(Path directory) {
    if (this.validationReportBuilder != null) {
      if (directory != null) {
        this.validationReportBuilder.saveXmlReports(directory);
      }
    }
  }

  /**
   * Set report validationReportBuilder.
   *
   * @param validationReportBuilder Report validationReportBuilder to use
   */
  public void generate(AsicValidationReportBuilder validationReportBuilder) {
    if (validationReportBuilder == null) {
      throw new IllegalArgumentException("Builder is unset");
    }
    this.validationReportBuilder = validationReportBuilder;
    this.buildResult();
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected String getResultName() {
    return "ASiC container";
  }

  private void buildResult() {
    if (this.validationReportBuilder != null) {
      this.report = this.validationReportBuilder.buildXmlReport();
      this.reports = this.validationReportBuilder.buildSignatureValidationReports();
      this.simpleReports = this.validationReportBuilder.buildSignatureSimpleReports();
    }
  }

  private SimpleReport getSimpleReport() {
    if (CollectionUtils.isNotEmpty(this.simpleReports)) {
      return this.simpleReports.get(0);
    }
    return null;
  }

  private SimpleReport getSimpleReportBySignatureId(String signatureId) {
    for (SimpleReport report : this.simpleReports) {
      if (report.getFirstSignatureId().equals(signatureId)) {
        return report;
      }
    }
    return null;
  }

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerErrors;
  }

  /**
   * Set container errors only.
   *
   * @param containerErrors Discovered list of container errors
   */
  public void setContainerErrors(List<DigiDoc4JException> containerErrors) {
    this.containerErrors = containerErrors;
  }

}
