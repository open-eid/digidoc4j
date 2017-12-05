/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Permission;

import org.digidoc4j.main.DigiDoc4J;
import org.digidoc4j.main.DigiDoc4JUtilityException;
import org.junit.AfterClass;
import org.junit.BeforeClass;

public class DigiDoc4JTestHelper extends ConfigurationSingeltonHolder {

  @BeforeClass
  public static void setConfigurationToTest() {
    ConfigurationSingeltonHolder.reset();
    System.setProperty("digidoc4j.mode", "TEST");
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("testFiles/tmp"));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("bdoc") && fileName.startsWith("test")
            || fileName.endsWith("asics") && fileName.startsWith("test")) {
          Files.deleteIfExists(item);
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void callMainWithoutSystemExit(String[] params) {
    SecurityManager securityManager = System.getSecurityManager();
    forbidSystemExitCall();
    try {
      DigiDoc4J.main(params);
    } catch (DigiDoc4JUtilityException ignore) {
    }
    System.setSecurityManager(securityManager);
  }

  private static void forbidSystemExitCall() {
    final SecurityManager preventExitSecurityManager = new SecurityManager() {
      public void checkPermission(Permission permission) {
      }

      @Override
      public void checkExit(int status) {
        super.checkExit(status);
        throw new DigiDoc4JUtilityException(status, "preventing system exist");
      }
    };
    System.setSecurityManager(preventExitSecurityManager);
  }


}
