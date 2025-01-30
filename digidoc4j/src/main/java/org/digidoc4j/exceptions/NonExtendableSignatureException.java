/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.exceptions;

/**
 * Exception is thrown when a signature cannot be extended
 */
public class NonExtendableSignatureException extends DigiDoc4JException {

  /**
   * @param message error message
   */
  public NonExtendableSignatureException(String message) {
    super(message);
  }

  /**
   * @param message error message
   * @param cause cause of exception
   */
  public NonExtendableSignatureException(String message, Throwable cause) {
    super(message, cause);
  }
}
