package org.digidoc4j.impl.asic.asice;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;


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
   * @param configuration
   */
  public AsicEContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerPath
   */
  public AsicEContainer(String containerPath) {
    super(containerPath, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor for subclasses
   *
   * @param containerPath
   * @param containerType
   */
  protected AsicEContainer(String containerPath, String containerType) {
    super(containerPath, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerPath
   * @param configuration
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
   * @param stream
   */
  public AsicEContainer(InputStream stream) {
    super(stream, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream
   */
  protected AsicEContainer(InputStream stream, String containerType) {
    super(stream, containerType);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream
   * @param configuration
   */
  public AsicEContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream
   * @param configuration
   */
  protected AsicEContainer(InputStream stream, Configuration configuration, String containerType) {
    super(stream, configuration, containerType);
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

  protected String createUserAgent() {
    if (!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
  }
}
