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

/**
 * Wrapper of command line option. This holds argument name and the count of extra arguments
 *
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum ExecutionOption {

  IN("in", 1),
  DTS("dts", 1),
  ADD("add", 2),
  CERTIFICATE("cert", 1),
  EXTRACT("extract", 2),
  PKCS11("pkcs11", 2),
  PKCS12("pkcs12", 2),
  SIGNATURE("sig", 1),
  TYPE("type", 1),
  TST("tst", 0),
  TSPSOURCE("tspsource", 1),
  TSPSOURCEARCHIVE("tspsourcearchive", 1),
  DATST("datst", 1),
  REFDATST("refdatst", 1),
  VERIFY("verify", 0),
  REMOVE("remove", 1),
  PROFILE("profile", 1),
  ENCRYPTION("encryption", 1),
  NOAIAOCSP("noaiaocsp", 0),
  @Deprecated AIAOCSP("aiaocsp", 0),
  REPORTDIR("reportDir", 1),
  SHOWERRORS("showerrors", 0),

  DETACHED_XADES("xades", 0),
  DIGEST_FILE("digFile" , 3),
  XADES_OUTPUT_PATH("sigOutputPath" , 1),
  XADES_INPUT_PATH("sigInputPath" , 1);

  private final String name;
  private final int count;

  ExecutionOption(String name, int count) {
    this.name = name;
    this.count = count;
  }

  /*
   * ACCESSORS
   */

  public String getName() {
    return name;
  }

  public int getCount() {
    return count;
  }

}
