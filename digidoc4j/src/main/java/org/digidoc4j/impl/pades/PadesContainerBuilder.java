package org.digidoc4j.impl.pades;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.exceptions.NotYetImplementedException;

/**
 * Created by Andrei on 17.11.2017.
 */
public class PadesContainerBuilder extends ContainerBuilder {

  @Override
  protected PadesContainer createNewContainer() {
    throw new NotYetImplementedException();
  }

  @Override
  protected Container openContainerFromFile() {
    if (configuration == null) {
      return ContainerOpener.open(containerFilePath);
    } else {
      return ContainerOpener.open(containerFilePath, configuration);
    }
  }

  @Override
  protected Container openContainerFromStream() {
    throw new NotYetImplementedException();
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    return null;
  }
}
