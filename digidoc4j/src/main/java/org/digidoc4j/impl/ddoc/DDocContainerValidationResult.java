/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.ddoc.DigiDocException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Overview of errors and warnings for DDoc signature
 */
public class DDocContainerValidationResult extends DDocSignatureValidationResult implements ContainerValidationResult {

  private final Map<String, ValidationResult> signatureResultMap;

  /**
   * Constructor
   *
   * @param exceptions list of validation exceptions
   * @param openContainerExceptions list of exceptions encountered when opening the container
   * @param signatureResultMap mappings of validation results for individual signatures
   * @param documentFormat document format
   */
  public DDocContainerValidationResult(
          List<DigiDocException> exceptions,
          List<DigiDocException> openContainerExceptions,
          Map<String, ValidationResult> signatureResultMap,
          String documentFormat
  ) {
    super(exceptions, openContainerExceptions, documentFormat);
    this.signatureResultMap = signatureResultMap;
  }

  @Override
  public ValidationResult getValidationResult(String signatureId) {
    return Optional.ofNullable(signatureId).map(signatureResultMap::get).orElse(null);
  }

  @Override
  public List<String> getSignatureIdList() {
    return new ArrayList<>(signatureResultMap.keySet());
  }

  @Override
  public List<String> getTimestampIdList() {
    return Collections.emptyList();
  }

  @Override
  protected String getResultName() {
    return "DDoc container";
  }

}
