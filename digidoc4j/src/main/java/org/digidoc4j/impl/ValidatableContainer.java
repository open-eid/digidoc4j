/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import org.digidoc4j.ContainerValidationResult;

import java.util.Date;

/**
 * Represents an opaque container type whose contents can be validated against specific validation times.
 */
public interface ValidatableContainer {

  /**
   * Validate container against the specified validation time.
   *
   * @param validationTime validation time
   * @return container validation result
   */
  ContainerValidationResult validateAt(Date validationTime);

}
