package org.digidoc4j.impl.asic.asics;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.AsicESignatureOpener;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

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

  @Override
  public DataFile getTimeStampToken() {
    return timeStampToken;
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

  @Override
  protected List<Signature> parseSignatureFiles(List<DSSDocument> signatureFiles, List<DSSDocument> detachedContents) {
    Configuration configuration = getConfiguration();
    AsicESignatureOpener signatureOpener = new AsicESignatureOpener(detachedContents, configuration);
    List<Signature> signatures = new ArrayList<>(signatureFiles.size());
    for (DSSDocument signatureFile : signatureFiles) {
      List<AsicESignature> asicSignatures = signatureOpener.parse(signatureFile);
      signatures.addAll(asicSignatures);
    }
    return signatures;
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
    if (!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocAsicSUserAgent(profile);
    }
    return Helper.createBDocAsicSUserAgent();
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
