/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

/*
 * Thanks to Aleksandr Zhuikov (http://aleksz-programming.blogspot.com.ee/2014/02/restricting-system-resource-access-in.html)
 */
package org.digidoc4j.test;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.File;
import java.io.IOException;
import java.security.Permission;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * JUnit extension class for making sure that the code under test would not write anything to the file system.
 */
public class RestrictedExternalResourceExtension implements BeforeEachCallback, AfterEachCallback {
  private Collection<String> whiteList;
  private SecurityManager originalSecurityManager;

  public RestrictedExternalResourceExtension(String... whiteList) {
    this.whiteList = Arrays.stream(whiteList)
            .map(path -> {
              try {
                return new File(path).getCanonicalPath();
              } catch (IOException e) {
                return path;
              }
            })
            .collect(Collectors.toList());
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    originalSecurityManager = System.getSecurityManager();

    System.setSecurityManager(new SecurityManager() {

      @Override
      public void checkWrite(String file) {
        if (!isAllowedToWrite(file)) {
          throw new FileWritingRestrictedException();
        }
      }

      @Override
      public void checkPermission(Permission perm) {
        return;
      }
    });
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    System.setSecurityManager(originalSecurityManager);
  }

  private boolean isAllowedToWrite(String file) {
    try {
      String canonicalFile = new File(file).getCanonicalPath();
      for (String prefix : this.whiteList) {
        if (canonicalFile.startsWith(prefix)) {
          return true;
        }
      }
    } catch (IOException e) {
      return false;
    }
    return false;
  }

  /**
   * File writing operations happened when not allowed.
   */
  public static class FileWritingRestrictedException extends RuntimeException {
  }

}
