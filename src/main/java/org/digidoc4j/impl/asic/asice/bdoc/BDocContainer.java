/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.asice.bdoc;

import java.io.InputStream;
import java.io.OutputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param configuration
   */
  public BDocContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath
   */
  public BDocContainer(String containerPath) {
    super(containerPath);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath
   * @param configuration
   */
  public BDocContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream
   */
  public BDocContainer(InputStream stream) {
    super(stream);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream
   * @param configuration
   */
  public BDocContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }
}
