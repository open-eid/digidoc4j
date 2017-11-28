package org.digidoc4j.impl.bdoc.asic;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
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
  }

  public AsicSContainer(Configuration configuration) {
    super(configuration);
  }

  public AsicSContainer(String containerPath) {
    super(containerPath);
  }

  public AsicSContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
  }

  public AsicSContainer(InputStream stream) {
    super(stream);
  }

  public AsicSContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
  }

  @Override
  public String getType() {
    return AsicContainer.ASIC_S;
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
