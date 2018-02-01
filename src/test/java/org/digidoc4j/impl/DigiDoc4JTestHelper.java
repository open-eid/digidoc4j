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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Permission;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.main.DigiDoc4J;
import org.digidoc4j.main.DigiDoc4JUtilityException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DigiDoc4JTestHelper extends ConfigurationSingeltonHolder {

  @Rule
  public TestWatcher watcher = new TestWatcher() {

    private final Logger log = LoggerFactory.getLogger(DigiDoc4JTestHelper.class);

    @Override
    protected void starting(Description description) {
      String starting = String.format("Starting --> %s.%s", description.getClassName(), description.getMethodName());
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
      this.log.info(starting);
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
    }

    @Override
    protected void succeeded(Description description) {
      this.log.info("Finished --> {}.{}", description.getClassName(), description.getMethodName());
    }

    @Override
    protected void failed(Throwable e, Description description) {
      this.log.error(String.format("Finished --> %s.%s", description.getClassName(), description.getMethodName()), e);
    }

    @Override
    protected void skipped(AssumptionViolatedException e, Description description) {
      String skipped = String.format("Skipped --> %s.%s", description.getClassName(), description.getMethodName());
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
      this.log.debug(skipped);
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
    }

  };

  @BeforeClass
  public static void setConfigurationToTest() {
    ConfigurationSingeltonHolder.reset();
    System.setProperty("digidoc4j.mode", "TEST");
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("src/test/resources/testFiles/tmp"));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("bdoc") && fileName.startsWith("test")
            || fileName.endsWith("asics") && fileName.startsWith("test")
            || fileName.endsWith("asice") && fileName.startsWith("test")) {
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
        throw new DigiDoc4JUtilityException(status, "preventing system exit");
      }
    };
    System.setSecurityManager(preventExitSecurityManager);
  }

  protected String getTxtFiles(InputStream in)  {
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    String line;
    StringBuilder content = new StringBuilder();
    try {
      while ((line = reader.readLine()) != null) {
        content.append(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    return content.toString();
  }

}
