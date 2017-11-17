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
public abstract class AsicEContainer extends AsicContainer {

  private static final Logger logger = LoggerFactory.getLogger(AsicEContainer.class);

  public AsicEContainer() {
    super();
  }

  public AsicEContainer(Configuration configuration) {
    super(configuration);
  }

  public AsicEContainer(String containerPath) {
    super(containerPath);
  }

  public AsicEContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration);
  }

  public AsicEContainer(InputStream stream) {
    super(stream);
  }

  public AsicEContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration);
  }

  @Override
  public String getType() {
    return AsicContainer.BDOC;
  }

  protected String createUserAgent() {
    if(!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
  }
}
