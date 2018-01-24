package org.digidoc4j.impl.asic.asics;

import java.io.Serializable;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Andrei on 10.11.2017.
 */
public class AsicSContainerBuilder extends ContainerBuilder implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(AsicSContainerBuilder.class);

  protected Container createNewContainer() {
    if (configuration == null) {
      return new AsicSContainer();
    } else {
      return new AsicSContainer(configuration);
    }
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    logger.warn("BDoc containers don't support setting temp directories");
    return this;
  }

}
