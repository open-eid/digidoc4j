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

import eu.europa.esig.dss.enumerations.TimestampQualification;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractContainerValidationResult extends AbstractSignatureValidationResult implements ContainerValidationResult {

  private static final Logger log = LoggerFactory.getLogger(AbstractContainerValidationResult.class);

  protected List<TimestampValidationReport> timestampReports = new ArrayList<>();
  protected List<DigiDoc4JException> containerErrors = new ArrayList<>();
  protected List<DigiDoc4JException> containerWarnings = new ArrayList<>();

  @Override
  public List<TimestampValidationReport> getTimestampReports() {
    return timestampReports;
  }

  @Override
  public TimestampQualification getTimestampQualification(String timestampId) {
    log.info(getNotSupportedMessage());
    return null;
  }

  @Override
  public List<DigiDoc4JException> getContainerErrors() {
    return containerErrors;
  }

  public void addContainerErrors(List<DigiDoc4JException> containerErrors) {
    this.containerErrors = concatenate(this.containerErrors, containerErrors);
  }

  public void setContainerErrors(List<DigiDoc4JException> containerErrors) {
    this.containerErrors = containerErrors;
  }

  @Override
  public List<DigiDoc4JException> getContainerWarnings() {
    return containerWarnings;
  }

  public void addContainerWarnings(List<DigiDoc4JException> containerWarnings) {
    this.containerWarnings = concatenate(this.containerWarnings, containerWarnings);
  }

  public void setContainerWarnings(List<DigiDoc4JException> containerWarnings) {
    this.containerWarnings = containerWarnings;
  }

}
