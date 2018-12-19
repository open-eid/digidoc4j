/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.exceptions.NotSupportedException;

/**
 * DDOC container builder
 */
public class DDocContainerBuilder extends ContainerBuilder {

  private String temporaryDirectoryPath;

  protected Container createNewContainer() {
    throw new NotSupportedException("Creating new container is not supported anymore for DDoc!");
  }

  @Override
  protected Container openContainerFromFile() {
    DDocOpener opener = createDocOpener();
    if (configuration == null) {
      return opener.open(containerFilePath);
    } else {
      return opener.open(containerFilePath, configuration);
    }
  }

  @Override
  protected Container openContainerFromStream() {
    DDocOpener opener = createDocOpener();
    if (configuration == null) {
      return opener.open(containerInputStream);
    }
    return opener.open(containerInputStream, configuration);
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    this.temporaryDirectoryPath = temporaryDirectoryPath;
    return this;
  }

  private DDocOpener createDocOpener() {
    DDocOpener opener = new DDocOpener();
    if (isNotBlank(temporaryDirectoryPath)) {
      opener.useTemporaryDirectoryPath(temporaryDirectoryPath);
    }
    return opener;
  }

}
