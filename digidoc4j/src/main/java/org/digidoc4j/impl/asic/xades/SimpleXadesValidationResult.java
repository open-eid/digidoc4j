/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import org.digidoc4j.impl.SimpleValidationResult;
import org.digidoc4j.impl.asic.xades.validation.XadesValidationResult;

import java.util.Objects;

/**
 * An extension to {@link SimpleValidationResult} to incorporate XAdES-specific validation data.
 */
public class SimpleXadesValidationResult extends SimpleValidationResult implements XadesValidationResult.Holder {

  private final XadesValidationResult xadesValidationResult;

  /**
   * @param validationName name of validation result
   * @param xadesValidationResult XAdES validation result
   */
  public SimpleXadesValidationResult(String validationName, XadesValidationResult xadesValidationResult) {
    super(validationName);
    this.xadesValidationResult = Objects.requireNonNull(xadesValidationResult);
  }

  @Override
  public XadesValidationResult getXadesValidationResult() {
    return xadesValidationResult;
  }

}
