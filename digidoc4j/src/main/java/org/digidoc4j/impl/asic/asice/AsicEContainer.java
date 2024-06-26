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

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureContainerMatcherValidator;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.IllegalSignatureProfileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.AsicContainerValidator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by Andrei on 7.11.2017.
 */
public class AsicEContainer extends AsicContainer {

  private static final String NOT_FOR_THIS_CONTAINER = "Not for ASiC-E container";

  /**
   * AsicEContainer constructor.
   */
  public AsicEContainer() {
    super();
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor.
   *
   * @param configuration configuration
   */
  public AsicEContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor.
   *
   * @param containerPath path
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public AsicEContainer(String containerPath) {
    super(containerPath, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor for subclasses.
   *
   * @param containerPath path
   * @param containerType type
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  protected AsicEContainer(String containerPath, String containerType) {
    super(containerPath, containerType);
  }

  /**
   * AsicEContainer constructor.
   *
   * @param containerPath path
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public AsicEContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor for subclasses.
   *
   * @param containerPath
   * @param configuration
   * @param containerType
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  protected AsicEContainer(String containerPath, Configuration configuration, String containerType) {
    super(containerPath, configuration, containerType);
  }

  /**
   * AsicEContainer constructor.
   *
   * @param stream input stream
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public AsicEContainer(InputStream stream) {
    super(stream, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor.
   *
   * @param stream input stream
   * @param containerType type
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  protected AsicEContainer(InputStream stream, String containerType) {
    super(stream, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public AsicEContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream input stream
   * @param configuration configuration
   * @param containerType type
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  protected AsicEContainer(InputStream stream, Configuration configuration, String containerType) {
    super(stream, configuration, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   */
  public AsicEContainer(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   * @param containerType container type
   *
   * @deprecated Deprecated for removal. Use {@link #AsicEContainer(AsicParseResult, Configuration)} instead.
   */
  @Deprecated
  protected AsicEContainer(AsicParseResult containerParseResult, Configuration configuration, String containerType) {
    super(containerParseResult, configuration, containerType);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out, getConfiguration()));
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new AsicESignatureOpener(getConfiguration());
  }

  @Override
  protected AsicContainerValidator getContainerValidator(AsicParseResult containerParseResult, boolean dataFilesHaveChanged) {
    if (containerParseResult != null) {
      return new AsicEContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
    } else {
      return new AsicEContainerValidator(getConfiguration());
    }
  }

  protected String createUserAgent() {
    return Constant.USER_AGENT_STRING;
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

  @Override
  protected void validateIncomingSignature(Signature signature) {
    super.validateIncomingSignature(signature);
    if (SignatureContainerMatcherValidator.isBDocOnlySignature(signature.getProfile()) && isAsicEContainer()) {
      throw new IllegalSignatureProfileException(
              "Cannot add BDoc specific (" + signature.getProfile() + ") signature to ASiCE container");
    }
  }

  private boolean isAsicEContainer() {
    return StringUtils.equals(Container.DocumentType.ASICE.name(), getType());
  }
}
