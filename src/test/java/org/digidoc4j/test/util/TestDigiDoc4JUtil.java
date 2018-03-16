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

import java.security.Permission;

import org.digidoc4j.main.DigiDoc4J;
import org.digidoc4j.main.DigiDoc4JUtilityException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestDigiDoc4JUtil {

  private static final SecurityManager preventExitSecurityManager = new SecurityManager() {

    @Override
    public void checkPermission(Permission permission) {
    }

    @Override
    public void checkExit(int status) {
      super.checkExit(status);
      throw new DigiDoc4JUtilityException(status, "Preventing system exit");
    }

  };

  public static void call(String[] params) {
    SecurityManager securityManager = System.getSecurityManager();
    System.setSecurityManager(TestDigiDoc4JUtil.preventExitSecurityManager);
    try {
      DigiDoc4J.main(params);
    } catch (DigiDoc4JUtilityException ignore) {
    }
    System.setSecurityManager(securityManager);
  }

}
