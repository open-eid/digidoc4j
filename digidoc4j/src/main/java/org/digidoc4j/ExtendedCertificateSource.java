package org.digidoc4j;

import java.io.FileFilter;
import java.nio.file.Path;

import eu.europa.esig.dss.spi.x509.CertificateSource;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public interface ExtendedCertificateSource extends CertificateSource {

  /**
   * Loads all certificates from path location
   *
   * @param path   folder to load
   */
  void importFromPath(Path path);

  /**
   * Loads all certificates from path location by filter
   *
   * @param path   folder to load
   * @param filter filter
   */
  void importFromPath(Path path, FileFilter filter);

}
