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
 * Container without files exception
 */
public class ContainerWithoutFilesException extends DigiDoc4JException {

  public static final String MESSAGE = "Container does not contain any data files";

  public ContainerWithoutFilesException() {
    super(MESSAGE);
  }

  /**
   * @param message error message
   */
  public ContainerWithoutFilesException(String message) {
    super(message);
  }

}
