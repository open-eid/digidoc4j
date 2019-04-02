/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asice;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by Andrei on 7.11.2017.
 */
public class AsicEContainer extends AsicContainer {

  private static final Logger logger = LoggerFactory.getLogger(AsicEContainer.class);

  /**
   * AsicEContainer constructor
   */
  public AsicEContainer() {
    super();
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param configuration configuration
   */
  public AsicEContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerPath path
   */
  public AsicEContainer(String containerPath) {
    super(containerPath, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor for subclasses
   *
   * @param containerPath path
   * @param containerType type
   */
  protected AsicEContainer(String containerPath, String containerType) {
    super(containerPath, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerPath path
   * @param configuration configuration
   */
  public AsicEContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor for subclasses
   *
   * @param containerPath
   * @param configuration
   * @param containerType
   */
  protected AsicEContainer(String containerPath, Configuration configuration, String containerType) {
    super(containerPath, configuration, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   */
  public AsicEContainer(InputStream stream) {
    super(stream, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   * @param containerType type
   */
  protected AsicEContainer(InputStream stream, String containerType) {
    super(stream, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   * @param configuration configuration
   */
  public AsicEContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   * @param configuration configuration
   * @param containerType type
   */
  protected AsicEContainer(InputStream stream, Configuration configuration, String containerType) {
    super(stream, configuration, containerType);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new AsicESignatureOpener(getConfiguration());
  }

  protected String createUserAgent() {
    if (!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
  }

  @Override
  public DataFile getTimeStampToken() {
    throw new NotSupportedException("Not for ASiC-E container");
  }
}
