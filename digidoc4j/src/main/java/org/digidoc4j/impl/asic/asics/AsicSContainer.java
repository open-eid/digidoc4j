/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.asice.AsicESignatureOpener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by Andrei on 7.11.2017.
 */
public class AsicSContainer extends AsicContainer {

  private static final Logger logger = LoggerFactory.getLogger(AsicSContainer.class);

  public AsicSContainer() {
    super();
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * @param configuration configuration
   */
  public AsicSContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * @param containerPath path
   */
  public AsicSContainer(String containerPath) {
    super(containerPath, Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * @param containerPath path
   * @param configuration configuration
   */
  public AsicSContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * @param stream input stream
   */
  public AsicSContainer(InputStream stream) {
    super(stream, Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * @param stream input stream
   * @param configuration configuration
   */
  public AsicSContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * AsicSContainer constructor
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   */
  public AsicSContainer(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration, Constant.ASICS_CONTAINER_TYPE);
  }

  @Override
  public DataFile getTimeStampToken() {
    return timeStampToken;
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new AsicESignatureOpener(getConfiguration());
  }

  /**
   * Replace Data File in AsicS container
   *
   * @param dataFile
   */
  public void replaceDataFile(DataFile dataFile){
    if (getDataFiles().size() > 0){
      removeDataFile(getDataFiles().get(0));
    }
    addDataFile(dataFile);
  }

  protected String createUserAgent() {
    return Constant.USER_AGENT_STRING;
  }

  @Override
  public void addSignature(Signature signature) {
    throw new NotSupportedException("Not for ASiC-S container");
  }

  @Override
  @Deprecated
  public void addRawSignature(byte[] signatureDocument) {
    throw new NotSupportedException("Not for ASiC-S container");
  }

  @Override
  @Deprecated
  public void addRawSignature(InputStream signatureStream) {
    throw new NotSupportedException("Not for ASiC-S container");
  }
}
