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

import static org.digidoc4j.test.util.OutputCaptureUtils.captureStdOut;

public final class TestDigiDoc4JUtil {

  public static int invokeDigiDoc4jAndReturnExitStatus(String... params) {
    return DigiDoc4J.executeAndReturnExitStatus(params);
  }

  public static InvocationResult invokeDigiDoc4jAndReturnInvocationResult(String... params) {
    final InvocationResult invocationResult = new InvocationResult();
    String capturedStdOut = captureStdOut(() -> {
      int returnedExitStatus = invokeDigiDoc4jAndReturnExitStatus(params);
      invocationResult.setExitStatus(returnedExitStatus);
    });
    invocationResult.setStdOut(capturedStdOut);
    return invocationResult;
  }
}
