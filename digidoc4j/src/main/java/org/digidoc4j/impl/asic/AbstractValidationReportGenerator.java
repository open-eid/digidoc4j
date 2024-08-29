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

import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Objects;

/**
 * An abstract base class for validation report generators.
 */
public abstract class AbstractValidationReportGenerator implements Serializable {

  private static final Logger log = LoggerFactory.getLogger(AbstractValidationReportGenerator.class);

  protected final Configuration configuration;

  private transient SignedDocumentValidator signedDocumentValidator;
  private transient Reports reports;

  /**
   * Creates an instance of a validation report generator.
   *
   * @param configuration configuration to use
   */
  protected AbstractValidationReportGenerator(Configuration configuration) {
    this.configuration = Objects.requireNonNull(configuration);
  }

  /**
   * Returns previously cached {@link Reports} or generates and returns new reports based on current state of this
   * report generator, if no reports have not been generated and cached before.
   * The newly generated reports are cached for later re-use.
   *
   * @return previously cached or newly generated reports
   */
  public Reports openValidationReport() {
    if (reports == null) {
      reports = generateReports();
      print();
    }
    return reports;
  }

  /**
   * Validates the state of this validation report generator against the specified validation time,
   * and generates and returns new {@link Reports} based on the fresh validation results.
   *
   * @param validationTime validation time
   * @return newly generated reports
   */
  public abstract Reports generateReports(Date validationTime);

  /**
   * Generates and returns new {@link Reports} based on current state of this report generator.
   *
   * @return newly generated reports
   */
  protected abstract Reports generateReports();

  /**
   * Returns previously cached {@link SignedDocumentValidator} or creates and returns a new validator based on the
   * current state of this validation report generator.
   * The newly created signed document validator is cached for later re-use.
   *
   * @return previously cached or newly created signed document validator
   */
  protected SignedDocumentValidator getSignedDocumentValidator() {
    if (signedDocumentValidator == null) {
      signedDocumentValidator = createValidator();
    }
    return signedDocumentValidator;
  }

  /**
   * Creates and returns a new {@link SignedDocumentValidator} based on the current state of this validation report
   * generator.
   *
   * @return newly created signed document validator
   */
  protected abstract SignedDocumentValidator createValidator();

  /**
   * Calls {@link SignedDocumentValidator#validateDocument(InputStream)} of the specified validator, emitting the
   * reports returned by the called method.
   * This method uses the validation policy specified in the {@link Configuration} that this report generator uses.
   *
   * @param signedDocumentValidator signed document validator to use for validation
   * @return reports emitted by validation
   */
  protected Reports validate(SignedDocumentValidator signedDocumentValidator) {
    try (InputStream validationPolicyInputStream = getValidationPolicyAsStream()) {
      return signedDocumentValidator.validateDocument(validationPolicyInputStream);
    } catch (IOException e) {
        throw new TechnicalException("Failed to load validation policy", e);
    }
  }

  private InputStream getValidationPolicyAsStream() {
    String policyFile = configuration.getValidationPolicy();
    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException e) {
        log.warn(e.getMessage());
      }
    }
    return this.getClass().getClassLoader().getResourceAsStream(policyFile);
  }

  private void print() {
    if (log.isTraceEnabled()) {
      log.trace("----------------Validation report---------------");
      log.trace(reports.getXmlDetailedReport());
      log.trace("----------------Simple report-------------------");
      log.trace(reports.getXmlSimpleReport());
    }
  }

}
