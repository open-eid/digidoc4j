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

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;

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
   * @param configuration configuration
   */
  public BDocContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath path
   */
  public BDocContainer(String containerPath) {
    super(containerPath, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param containerPath path
   * @param configuration configuration
   */
  public BDocContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream input stream
   */
  public BDocContainer(InputStream stream) {
    super(stream, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor
   *
   * @param stream input stream
   * @param configuration configuration
   */
  public BDocContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.BDOC_CONTAINER_TYPE);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new BDocSignatureOpener(getConfiguration());
  }

  @Override
  public DataFile getTimeStampToken() {
    throw new NotSupportedException("Not for BDOC container");
  }
}
