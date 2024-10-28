/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test;

import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.List;

public class MockValidationResult implements ValidationResult {

  private boolean valid;
  private boolean hasWarnings;
  private List<DigiDoc4JException> errors;
  private List<DigiDoc4JException> warnings;

  @Override
  public boolean isValid() {
    return valid;
  }

  public void setValid(boolean valid) {
    this.valid = valid;
  }

  @Override
  public boolean hasWarnings() {
    return hasWarnings;
  }

  public void setHasWarnings(boolean hasWarnings) {
    this.hasWarnings = hasWarnings;
  }

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
