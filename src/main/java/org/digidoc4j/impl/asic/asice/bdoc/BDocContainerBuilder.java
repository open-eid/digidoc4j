package org.digidoc4j.impl.asic.asice.bdoc;

import java.io.Serializable;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.impl.asic.asice.AsicEContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Andrei on 10.11.2017.
 */
public class BDocContainerBuilder extends AsicEContainerBuilder implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainerBuilder.class);

  protected Container createNewContainer() {
    if (configuration == null) {
      return new BDocContainer();
    } else {
      return new BDocContainer(configuration);
    }
  }
  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    logger.warn("BDoc containers don't support setting temp directories");
    return this;
  }

}
