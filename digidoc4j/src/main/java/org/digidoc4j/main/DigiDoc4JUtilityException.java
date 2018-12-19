/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.main;

import org.digidoc4j.exceptions.DigiDoc4JException;

/**
 * Exceptions thrown by DigiDoc4JUtility
 */
public class DigiDoc4JUtilityException extends DigiDoc4JException {

  private final int errorCode;

  /**
   * Throws exception with message
   *
   * @param message error message
   */

  public DigiDoc4JUtilityException(String message) {
    this(2, message);
  }

  /**
   * Throws exception with error code and message
   *
   * @param errorCode error code
   * @param message   error message
   */
  public DigiDoc4JUtilityException(int errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  /**
   * @param errorCode error code
   * @param cause cause
   */
  public DigiDoc4JUtilityException(int errorCode, Throwable cause) {
    super(cause);
    this.errorCode = errorCode;
  }

  /**
   * Returns error code
   *
   * @return error code
   */
  public int getErrorCode() {
    return errorCode;
  }

}
