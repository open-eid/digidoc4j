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

public class RemovingDataFileException extends DigiDoc4JException {

  public static final String MESSAGE = "Datafiles cannot be removed from an already signed container";

  public RemovingDataFileException() {
    super(MESSAGE);
  }
}
