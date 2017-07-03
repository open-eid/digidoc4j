package org.digidoc4j.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.tsl.TslLoader;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;

public class TSLHelper {

  /**
   * This might be needed to validate already created containers that use test certificates but are timestamped by live TSA
   * @param configuration the configuration to add the certificate.
   * @return the same configuration with certificate added to TSL
   */
  public static Configuration addSkTsaCertificateToTsl(Configuration configuration) {
    return addCertificateFromFileToTsl(configuration, "testFiles/certs/SK_TSA.pem.crt");
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

  public static long getCacheLastModificationTime() {
    File cachedFile = getCachedFile(TslLoader.fileCacheDirectory);
    return cachedFile.lastModified();
  }

  public static boolean isTslCacheEmpty() {
    if(!TslLoader.fileCacheDirectory.exists()) {
      return true;
    }
    File[] cachedFiles = TslLoader.fileCacheDirectory.listFiles();
    return cachedFiles == null || cachedFiles.length == 0;
  }

  public static void deleteTSLCache() {
    TslLoader.invalidateCache();
  }

  private static File getCachedFile(File cacheDirectory) {
    File cachedFile = null;
    if(cacheDirectory.exists()) {
      File[] files = cacheDirectory.listFiles();
      if(files != null && files.length > 0) {
        cachedFile = files[0];
        long modificationTime = cachedFile.lastModified();
        for(File file: files) {
          if(file.lastModified() > modificationTime) {
            cachedFile = file;
          }
        }
      }
    }
    return cachedFile;
  }
}
