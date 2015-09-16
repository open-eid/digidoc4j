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

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;

public class DDocContainerBuilder extends ContainerBuilder {

  protected DDocContainer createNewContainer() {
    if (configuration == null) {
      return new DDocContainer();
    } else {
      return new DDocContainer(configuration);
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
      boolean actAsBigFilesSupportEnabled = true; //Doesn't have any meaning for DDOC containers. Opportunity to refactor
      return ContainerOpener.open(containerInputStream, actAsBigFilesSupportEnabled);
    }
    return ContainerOpener.open(containerInputStream, configuration);
  }
}
