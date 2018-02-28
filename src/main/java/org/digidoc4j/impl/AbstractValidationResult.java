package org.digidoc4j.impl;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public abstract class AbstractValidationResult implements ValidationResult {

  private final Logger log = LoggerFactory.getLogger(AbstractValidationResult.class);
  protected List<DigiDoc4JException> errors = new ArrayList<>();
  protected List<DigiDoc4JException> warnings = new ArrayList<>();

  @Override
  public boolean isValid() {
    return errors.isEmpty();
  }

  @Override
  public boolean hasWarnings() {
    return CollectionUtils.isNotEmpty(this.warnings);
  }

  public void print() {
    boolean hasWarningsOnly = CollectionUtils.isNotEmpty(this.warnings) && this.isValid();
    if (hasWarningsOnly || CollectionUtils.isNotEmpty(this.errors)) {
      if (hasWarningsOnly) {
        Helper.printWarningSection(this.log, String.format("Start of <%s> validation result", this.getValidationName
            ()));
      } else {
        Helper.printErrorSection(this.log, String.format("Start of <%s> validation result", this.getValidationName()));
      }
      if (CollectionUtils.isNotEmpty(this.errors)) {
        for (DigiDoc4JException error : this.errors) {
          this.log.error(error.toString());
        }
      }
      if (CollectionUtils.isNotEmpty(this.warnings)) {
        for (DigiDoc4JException warning : this.warnings) {
          this.log.warn(warning.toString());
        }
      }
      if (hasWarningsOnly) {
        Helper.printWarningSection(this.log, String.format("End of <%s> validation result", this
            .getValidationName()));
      } else {
        Helper.printErrorSection(this.log, String.format("End of <%s> validation result", this.getValidationName()));
      }
    }
  }

  /*
   * RESTRICTED METHODS
   */

  protected abstract String getValidationName();

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  public void setErrors(List<DigiDoc4JException> errors) {
    this.errors = errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  public void setWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = warnings;
  }

}
