/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.asic.AsicContainer;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.AsicEContainer;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

/**
 * Offers functionality for handling data files and signatures in a container.
 */
public class BDocContainer extends AsicEContainer {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainer.class);

  /**
   * BDocContainer constructor
   */
  public BDocContainer() {
    super();
  }

  /**
   * BDocContainer constructor
   *
   * @param configuration
   */
  public BDocContainer(Configuration configuration) {
    super(configuration);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath
   */
  public BDocContainer(String containerPath) {
    super(containerPath);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath
   * @param configuration
   */
  public BDocContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream
   */
  public BDocContainer(InputStream stream) {
    super(stream);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream
   * @param configuration
   */
  public BDocContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }
}
