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
