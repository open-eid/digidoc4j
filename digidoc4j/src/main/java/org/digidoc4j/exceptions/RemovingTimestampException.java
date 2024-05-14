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

public class RemovingTimestampException extends DigiDoc4JException {

  public static final String MESSAGE = "Timestamp cannot be removed; it is covered by other timestamp(s)";

  public RemovingTimestampException() {
    super(MESSAGE);
  }
}
