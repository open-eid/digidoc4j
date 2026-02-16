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

public class InvocationResult {
  private int exitStatus;
  private String stdOut;

  public int getExitStatus() {
    return exitStatus;
  }

  public void setExitStatus(int exitStatus) {
    this.exitStatus = exitStatus;
  }

  public String getStdOut() {
    return stdOut;
  }

  public void setStdOut(String stdOut) {
    this.stdOut = stdOut;
  }

}
