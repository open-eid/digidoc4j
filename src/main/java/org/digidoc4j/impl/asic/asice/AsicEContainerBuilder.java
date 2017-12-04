package org.digidoc4j.impl.asic.asice;

import java.io.Serializable;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Andrei on 10.11.2017.
 */
public class AsicEContainerBuilder extends ContainerBuilder implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(AsicEContainerBuilder.class);

  protected BDocContainer createNewContainer() {
    if (configuration == null) {
      return new BDocContainer();
    } else {
      return new BDocContainer(configuration);
    }
  }

  protected Container openContainerFromFile() {
    if (configuration == null) {
      return ContainerOpener.open(containerFilePath);
    } else {
      return ContainerOpener.open(containerFilePath, configuration);
    }
  }

  protected Container openContainerFromStream() {
    if (configuration == null) {
      boolean actAsBigFilesSupportEnabled = true;
      return ContainerOpener.open(containerInputStream, actAsBigFilesSupportEnabled);
    }
    return ContainerOpener.open(containerInputStream, configuration);
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    logger.warn("BDoc containers don't support setting temp directories");
    return this;
  }

}
