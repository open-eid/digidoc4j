/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.AsicContainerValidationResult;

import java.util.Objects;
import java.util.stream.Stream;

public class AsicSTimestampedContainerValidationResult extends AsicContainerValidationResult {

  @Override
  public boolean isValid() {
    return super.isValid() || (hasValidTimestamps() && hasNoUnaccountedErrors());
  }

  private boolean hasValidTimestamps() {
    return getTimestampValidationResultStream().anyMatch(ValidationResult::isValid);
  }

  private boolean hasNoUnaccountedErrors() {
    // Ensures that all errors present in this container validation result, originate only from
    //  the validation results of invalid timestamps, and there are no unaccounted errors.
    return getErrors().stream().allMatch(e -> getTimestampValidationResultStream()
            .filter(AsicSTimestampedContainerValidationResult::isNotValid)
            .map(ValidationResult::getErrors)
            .anyMatch(es -> es.contains(e)));
  }

  private Stream<ValidationResult> getTimestampValidationResultStream() {
    return getTimestampIdList().stream()
            .map(this::getValidationResult)
            .filter(Objects::nonNull);
  }

  private static boolean isNotValid(ValidationResult validationResult) {
    return !validationResult.isValid();
  }

}
