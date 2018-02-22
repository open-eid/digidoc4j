package org.digidoc4j;

import java.io.FileFilter;
import java.nio.file.Path;

import eu.europa.esig.dss.x509.CertificateSource;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public interface CommonCertificateSource extends CertificateSource {

  /**
   * Loads all certificates from path location
   *
   * @param path   folder to load
   */
  void loadFromPath(Path path);

  /**
   * Loads all certificates from path location
   *
   * @param path   folder to load
   * @param filter filter
   */
  void loadFromPath(Path path, FileFilter filter);

}
