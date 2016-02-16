/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

public class SignatureValidationResult implements Serializable {

  private List<DigiDoc4JException> errors = new ArrayList<>();
  private List<DigiDoc4JException> warnings = new ArrayList<>();

  public boolean isValid() {
    return errors.isEmpty();
  }

  public List<DigiDoc4JException> getErrors() {
    return errors;
  }

  public void setErrors(List<DigiDoc4JException> errors) {
    this.errors = errors;
  }

  public List<DigiDoc4JException> getWarnings() {
    return warnings;
  }

  public void setWarnings(List<DigiDoc4JException> warnings) {
    this.warnings = warnings;
  }
}
