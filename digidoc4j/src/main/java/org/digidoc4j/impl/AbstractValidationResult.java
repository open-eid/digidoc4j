package org.digidoc4j.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public abstract class AbstractValidationResult implements ValidationResult {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractValidationResult.class);
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

  /**
   * @param configuration configuration context
   */
  public void print(Configuration configuration) {
    if (configuration.getPrintValidationReport()) {
      boolean hasWarningsOnly = CollectionUtils.isNotEmpty(this.warnings) && this.isValid();
      if (hasWarningsOnly || CollectionUtils.isNotEmpty(this.errors)) {
        if (hasWarningsOnly) {
          Helper.printWarningSection(LOGGER, String.format("Start of <%s> validation result", this.getResultName
              ()));
        } else {
          Helper.printErrorSection(LOGGER, String.format("Start of <%s> validation result", this.getResultName()));
        }
        if (CollectionUtils.isNotEmpty(this.errors)) {
          for (DigiDoc4JException error : this.errors) {
            LOGGER.error(error.toString());
          }
        }
        if (CollectionUtils.isNotEmpty(this.warnings)) {
          for (DigiDoc4JException warning : this.warnings) {
            LOGGER.warn(warning.toString());
          }
        }
        if (hasWarningsOnly) {
          Helper.printWarningSection(LOGGER, String.format("End of <%s> validation result", this
              .getResultName()));
        } else {
          Helper.printErrorSection(LOGGER, String.format("End of <%s> validation result", this.getResultName()));
        }
      }
    }
  }

  /*
   * RESTRICTED METHODS
   */

  protected abstract String getResultName();

  /*
   * ACCESSORS
   */

  @Override
  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  public void addErrors(List<DigiDoc4JException> errors) {
    this.errors = concatenate(this.errors, errors);
  }

  public void setErrors(List<DigiDoc4JException> errors) {
    this.errors = errors;
  }

  @Override
  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  public void addWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = concatenate(this.warnings, warnings);
  }

  public void setWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = warnings;
  }

  protected static List<DigiDoc4JException> concatenate(List<DigiDoc4JException> first, List<DigiDoc4JException> second) {
    return Stream.concat(
            Optional.ofNullable(first).map(List::stream).orElseGet(Stream::empty),
            Optional.ofNullable(second).map(List::stream).orElseGet(Stream::empty)
    ).collect(Collectors.toList());
  }

}
