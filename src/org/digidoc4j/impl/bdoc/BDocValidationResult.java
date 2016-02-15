/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;

public class BDocValidationResult implements ValidationResult {

  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();
  private List<DigiDoc4JException> containerErrorsOnly = new ArrayList<>();
  private BDocValidationReportBuilder reportBuilder;

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
  public List<DigiDoc4JException> getContainerErrors() {
    return containerErrorsOnly;
  }

  public void setContainerErrorsOnly(List<DigiDoc4JException> containerErrorsOnly) {
    this.containerErrorsOnly = containerErrorsOnly;
  }

  public void setErrors(List<DigiDoc4JException> errors) {
    this.errors = errors;
  }

  public void setWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = warnings;
  }

  public void setReportBuilder(BDocValidationReportBuilder reportBuilder) {
    this.reportBuilder = reportBuilder;
  }
}
