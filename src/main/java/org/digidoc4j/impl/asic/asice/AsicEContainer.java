package org.digidoc4j.impl.asic.asice;

import java.io.InputStream;
import java.io.OutputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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
    super(containerPath);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param containerPath
   * @param configuration
   */
  public AsicEContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream
   */
  public AsicEContainer(InputStream stream) {
    super(stream);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  /**
   * AsicEContainer constructor
   *
   * @param stream
   * @param configuration
   */
  public AsicEContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
    setType(Constant.ASICE_CONTAINER_TYPE);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
  }

  protected String createUserAgent() {
    if (!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
  }
}
