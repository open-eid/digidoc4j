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

import org.junit.Assert;
import org.junit.Test;

public class DigiDoc4JExceptionTest {

  @Test
  public void toStringWithNoErrorCode() throws Exception {
    DigiDoc4JException error = new DigiDoc4JException("Error");
    Assert.assertEquals("Error", error.toString());
  }

  @Test
  public void toStringWithErrorCode() throws Exception {
    DigiDoc4JException error = new DigiDoc4JException(5, "Error");
    Assert.assertEquals("ERROR: 5 - Error", error.toString());
  }

}
