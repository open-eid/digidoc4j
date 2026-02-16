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

import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;

public class OutputCaptureUtils {

  public static String captureStdOut(Runnable action) {
    try {
      return tapSystemOut(action::run);
    } catch (Exception e) {
      throw new RuntimeException("Failed to capture System.out", e);
    }
  }
}
