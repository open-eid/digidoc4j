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
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainerValidator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.asice.AsicEContainer;

import java.io.InputStream;

/**
 * Offers functionality for handling data files and signatures in a container.
 */
public class BDocContainer extends AsicEContainer {

  private static final String NOT_FOR_THIS_CONTAINER = "Not for BDOC container";

  /**
   * BDocContainer constructor.
   */
  public BDocContainer() {
    super();
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param configuration configuration
   */
  public BDocContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param containerPath path
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public BDocContainer(String containerPath) {
    super(containerPath, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param containerPath path
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public BDocContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param stream input stream
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public BDocContainer(InputStream stream) {
    super(stream, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param stream input stream
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public BDocContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.BDOC_CONTAINER_TYPE);
  }

  /**
   * BDocContainer constructor.
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   */
  public BDocContainer(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration, Constant.BDOC_CONTAINER_TYPE);
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new BDocSignatureOpener(getConfiguration());
  }

  @Override
  protected AsicContainerValidator getContainerValidator(AsicParseResult containerParseResult, boolean dataFilesHaveChanged) {
    if (containerParseResult != null) {
      return new BDocContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
    } else {
      return new BDocContainerValidator(getConfiguration());
    }
  }

  @Override
  public void addTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public void removeTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public DataFile getTimeStampToken() {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

}
