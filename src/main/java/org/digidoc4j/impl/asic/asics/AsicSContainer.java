package org.digidoc4j.impl.asic.asics;

import java.io.InputStream;
import java.io.OutputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Andrei on 7.11.2017.
 */
public class AsicSContainer extends AsicContainer {

  private static final Logger logger = LoggerFactory.getLogger(AsicSContainer.class);

  public AsicSContainer() {
    super();
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  public AsicSContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  public AsicSContainer(String containerPath) {
    super(containerPath);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  public AsicSContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  public AsicSContainer(InputStream stream) {
    super(stream);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  public AsicSContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out));
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
}
