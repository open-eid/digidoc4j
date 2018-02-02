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
 * Created by Janar Rahumeel (CGI Estonia)
 */

public enum ExecutionOption {

  EXTERNAL("ext", 0),
  IN("in", 1),
  DIGEST("dig", 1),
  ADD("add", 2),
  CERTIFICATE("cert", 1),
  EXTRACT("extract", 2),
  PKCS11("pkcs11", 2),
  PKCS12("pkcs12", 2),
  SIGNAURE("sig", 1);

  private String name;
  private int count;

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
