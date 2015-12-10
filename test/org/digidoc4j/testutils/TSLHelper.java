package org.digidoc4j.testutils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.digidoc4j.Configuration;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;

public class TSLHelper {

  /**
   * This might be needed to validate already created containers that use test certificates but are timestamped by live TSA
   * @param configuration the configuration to add the certificate.
   * @return the same configuration with certificate added to TSL
   */
  public static Configuration addSkTsaCertificateToTsl(Configuration configuration) {
    return addCertificateFromFileToTsl(configuration, "testFiles/SK_TSA.pem.crt");
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
}
