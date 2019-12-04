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
 * Exeptions related to digidoc4J configuration settings
 */
public class ConfigurationException extends DigiDoc4JException {
  /**
   * Create a configuration exception with give message
   *
   * @param message Message for the exception
   */
  public ConfigurationException(String message) {
    super(message);
  }

  /**
   * Create a configuration exception with give message and cause
   *
   * @param message Message for the exception
   * @param cause Cause of exception
   */
  public ConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}
