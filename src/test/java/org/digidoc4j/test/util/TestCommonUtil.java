/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test.util;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestCommonUtil {

  public static void sleepInSeconds(int seconds) {
    try {
      Thread.sleep(seconds * 1000);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}
