/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.impl.bdoc.AsicFacade;
import org.digidoc4j.impl.ddoc.DDocFacade;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainer;

public class ContainerBuilder {

  public static final String BDOC_CONTAINER_TYPE = "BDOC";
  public static final String DDOC_CONTAINER_TYPE = "DDOC";
  private String containerType = BDOC_CONTAINER_TYPE;
  private Configuration configuration;
  private List<ContainerDataFile> dataFiles = new ArrayList<>();

  public static ContainerBuilder aContainer() {
    return new ContainerBuilder();
  }

  public Container build() {
    Container container;
    if (StringUtils.equalsIgnoreCase(containerType, DDOC_CONTAINER_TYPE)) {
      DDocFacade containerImpl = createDDocContainer();
      container = new DDocContainer(containerImpl);
    } else {
      AsicFacade asicFacade = createBDocContainer();
      container = new BDocContainer(asicFacade);
    }
    addDataFilesToContainer(container);
    return container;
  }

  public ContainerBuilder withType(String containerType) {
    this.containerType = containerType;
    return this;
  }

  public ContainerBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  public ContainerBuilder withDataFile(String filePath, String mimeType) {
    dataFiles.add(new ContainerDataFile(filePath, mimeType));
    return this;
  }

  public ContainerBuilder withDataFile(InputStream inputStream, String fileName, String mimeType) {
    dataFiles.add(new ContainerDataFile(inputStream, fileName, mimeType));
    return this;
  }

  public ContainerBuilder withDataFile(File file, String mimeType) {
    dataFiles.add(new ContainerDataFile(file.getPath(), mimeType));
    return this;
  }

  private AsicFacade createBDocContainer() {
    if (configuration == null) {
      return new AsicFacade();
    } else {
      return new AsicFacade(configuration);
    }
  }

  private DDocFacade createDDocContainer() {
    if (configuration == null) {
      return new DDocFacade();
    } else {
      return new DDocFacade(configuration);
    }
  }

  private void addDataFilesToContainer(Container container) {
    for (ContainerDataFile file : dataFiles) {
      if (file.isStream) {
        container.addDataFile(file.inputStream, file.filePath, file.mimeType);
      } else {
        container.addDataFile(file.filePath, file.mimeType);
      }
    }
  }

  private class ContainerDataFile {

    String filePath;
    String mimeType;
    InputStream inputStream;
    boolean isStream;

    public ContainerDataFile(String filePath, String mimeType) {
      this.filePath = filePath;
      this.mimeType = mimeType;
      isStream = false;
    }

    public ContainerDataFile(InputStream inputStream, String filePath, String mimeType) {
      this.filePath = filePath;
      this.mimeType = mimeType;
      this.inputStream = inputStream;
      isStream = true;
    }
  }
}
