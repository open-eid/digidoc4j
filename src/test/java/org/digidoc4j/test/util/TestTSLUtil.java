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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.tsl.TslLoader;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestTSLUtil {

  /**
   * This might be needed to validate already created containers that use test certificates but are timestamped by live TSA
   * @param configuration the configuration to add the certificate.
   * @return the same configuration with certificate added to TSL
   */
  public static Configuration addSkTsaCertificateToTsl(Configuration configuration) {
    return TestTSLUtil.addCertificateFromFileToTsl(configuration, "src/test/resources/testFiles/certs/SK_TSA.pem.crt");
  }

  public static Configuration addCertificateFromFileToTsl(Configuration configuration, String fileName) {
    try {
      FileInputStream fileInputStream = new FileInputStream(fileName);
      X509Certificate certificate = DSSUtils.loadCertificate(fileInputStream).getCertificate();
      configuration.getTSL().addTSLCertificate(certificate);
      fileInputStream.close();
      return configuration;
    } catch (DSSException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void evictCache() {
    TslLoader.invalidateCache();
  }

  public static long getCacheLastModified() {
    return TestTSLUtil.getCachedFile(TslLoader.fileCacheDirectory).lastModified();
  }

  private static File getCachedFile(File cacheDirectory) { // TODO refactor
    File cachedFile = null;
    if (cacheDirectory.exists()) {
      File[] files = cacheDirectory.listFiles();
      if (files != null && files.length > 0) {
        cachedFile = files[0];
        long modificationTime = cachedFile.lastModified();
        for (File file : files) {
          if (file.lastModified() > modificationTime) {
            cachedFile = file;
          }
        }
      }
    }
    return cachedFile;
  }

  public static boolean isTslCacheEmpty() {
    if(!TslLoader.fileCacheDirectory.exists()) {
      return true;
    }
    File[] cachedFiles = TslLoader.fileCacheDirectory.listFiles();
    return cachedFiles == null || cachedFiles.length == 0;
  }

}
