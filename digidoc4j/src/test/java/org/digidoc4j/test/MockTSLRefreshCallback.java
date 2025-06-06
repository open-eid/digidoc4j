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

import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import org.digidoc4j.TSLRefreshCallback;

import java.util.Objects;

public class MockTSLRefreshCallback implements TSLRefreshCallback {

  private final boolean valueToReturn;
  private final RuntimeException exceptionToThrow;

  public MockTSLRefreshCallback(boolean valueToReturn) {
    this.valueToReturn = valueToReturn;
    this.exceptionToThrow = null;
  }

  public MockTSLRefreshCallback(RuntimeException exceptionToThrow) {
    this.exceptionToThrow = Objects.requireNonNull(exceptionToThrow);
    this.valueToReturn = false;
  }

  @Override
  public boolean ensureTSLState(TLValidationJobSummary summary) {
    if (exceptionToThrow != null) {
      throw exceptionToThrow;
    } else {
      return valueToReturn;
    }
  }

}
