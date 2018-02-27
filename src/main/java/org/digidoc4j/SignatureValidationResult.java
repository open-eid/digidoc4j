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

import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureValidationResult implements Serializable {

  private final Logger log = LoggerFactory.getLogger(SignatureValidationResult.class);
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

  public void print() {
    boolean hasWarningsOnly = CollectionUtils.isNotEmpty(this.warnings) && this.isValid();
    if (hasWarningsOnly || CollectionUtils.isNotEmpty(this.errors)) {
      if (hasWarningsOnly) {
        Helper.printWarningSection(this.log, "Start of signature validation result");
      } else {
        Helper.printErrorSection(this.log, "Start of signature validation result");
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
        Helper.printWarningSection(this.log, "End of signature validation result");
      } else {
        Helper.printErrorSection(this.log, "End of signature validation result");
      }
    }
  }

}
