package org.digidoc4j.impl.asic.asice;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * Created by Andrei on 10.11.2017.
 */
public class AsicEContainerBuilder extends ContainerBuilder implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(AsicEContainerBuilder.class);

  @Override
  protected Container createNewContainer() {
    if (configuration == null) {
      return new AsicEContainer();
    } else {
      return new AsicEContainer(configuration);
    }
  }

  @Override
  protected Container openContainerFromFile() {
    return overrideContainerIfNeeded(super.openContainerFromFile());
  }

  @Override
  protected Container openContainerFromStream() {
    return overrideContainerIfNeeded(super.openContainerFromStream());
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    logger.warn("ASiCE containers don't support setting temp directories");
    return this;
  }

  /**
   * DD4J-414 - hackish solution for building BDoc container from existing container with no signatures.
   * ContainerOpener considers any Asic container without signatures that is not ASiCS, a ASiCE by default.
   * In the future ContainerOpener should take container type as an input to force BDoc when needed.
   * At the moment did not want to change ContainerOpener API, that will be done with major release with
   * more API changes.
   *
   * TODO: Should be refactored away in task -
   */
  private Container overrideContainerIfNeeded(Container container) {
    if (container instanceof AsicEContainer && container.getSignatures().isEmpty()) {
      AsicContainer asicContainer = (AsicContainer) container;
      if (isContainerOverrideNeeded(asicContainer)) {
        AsicParseResult containerParseResult = asicContainer.getContainerParseResult();
        Configuration configuration = container.getConfiguration();
        return overrideContainer(containerParseResult, configuration);
      }
    }
    return container;
  }

  protected boolean isContainerOverrideNeeded(AsicContainer asicContainer) {
    return !Container.DocumentType.ASICE.name().equals(asicContainer.getType());
  }

  protected Container overrideContainer(AsicParseResult asicParseResult, Configuration configuration) {
    return new AsicEContainer(asicParseResult, configuration);
  }

}
