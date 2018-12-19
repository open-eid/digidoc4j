package org.digidoc4j.impl;

import java.io.File;
import java.io.FileFilter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.digidoc4j.ExtendedCertificateSource;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class CommonOCSPCertificateSource extends CommonCertificateSource implements ExtendedCertificateSource {

  private static final Logger logger = LoggerFactory.getLogger(CommonOCSPCertificateSource.class);

  /**
   * Loads all certificates found from classpath
   */
  public CommonOCSPCertificateSource() {
    this.certificateTokens = new ArrayList<>();
    this.initialize();
  }

  @Override
  public void importFromPath(Path path) {
    this.importFromPath(path, new Helper.FileExtensionFilter("crt"));
  }

  @Override
  public void importFromPath(Path path, FileFilter filter) {
    logger.info("Loading OCSP certificates from <{}>", path);
    this.loadFiles(Helper.getFilesFromPath(path, filter));
  }

  /*
   * RESTRICTED METHODS
   */

  private void initialize() {
    if (this.getCertificatePool().getNumberOfCertificates() == 0) {
      logger.info("Initializing OCSP certificate source ...");
      this.loadFiles(Helper.getFilesFromResourcePath(Paths.get("ocsp"), new Helper.FileExtensionFilter("crt")));
    }
  }

  private void loadFiles(File... files) {
    for (File file : files) {
      logger.debug("Loading certificate from <{}>", file);
      if (file.isFile() && file.canRead()) {
        try {
          this.addCertificate(new CertificateToken(Helper.loadCertificate(file.getPath())));
        } catch (Exception e) {
          logger.warn("Unable to load OCSP certificate from <{}>", file.getPath());
        }
      }
    }
    logger.info("OCSP certificate source contains <{}> additional certificate(s)",
        this.getCertificatePool().getNumberOfCertificates());
  }

}
