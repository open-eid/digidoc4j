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
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.CustomContainerBuilder;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.impl.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ContainerBuilder {

  private static final Logger logger = LoggerFactory.getLogger(ContainerBuilder.class);

  public static final String BDOC_CONTAINER_TYPE = "BDOC";
  public static final String DDOC_CONTAINER_TYPE = "DDOC";
  protected static Map<String, Class<? extends Container>> containerImplementations = new HashMap<>();
  protected Configuration configuration;
  protected List<ContainerDataFile> dataFiles = new ArrayList<>();
  protected String containerFilePath;
  protected InputStream containerInputStream;

  protected abstract Container createNewContainer();

  protected abstract Container openContainerFromFile();

  protected abstract Container openContainerFromStream();

  public static ContainerBuilder aContainer() {
    return new BDocContainerBuilder();
  }

  public static ContainerBuilder aContainer(String containerType) {
    if (isCustomContainerType(containerType)) {
      return new CustomContainerBuilder(containerType);
    }
    switch (containerType) {
      case BDOC_CONTAINER_TYPE:
        return new BDocContainerBuilder();
      case DDOC_CONTAINER_TYPE:
        return new DDocContainerBuilder();
    }
    throw new NotSupportedException("Container type is not supported: " + containerType);
  }

  public Container build() {
    if (shouldOpenContainerFromFile()) {
      return openContainerFromFile();
    } else if (shouldOpenContainerFromStream()) {
      return openContainerFromStream();
    }
    Container container = createNewContainer();
    addDataFilesToContainer(container);
    return container;
  }

  public ContainerBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  public ContainerBuilder withDataFile(String filePath, String mimeType) throws InvalidDataFileException {
    dataFiles.add(new ContainerDataFile(filePath, mimeType));
    return this;
  }

  public ContainerBuilder withDataFile(InputStream inputStream, String fileName, String mimeType) throws InvalidDataFileException {
    dataFiles.add(new ContainerDataFile(inputStream, fileName, mimeType));
    return this;
  }

  public ContainerBuilder withDataFile(File file, String mimeType) throws InvalidDataFileException {
    dataFiles.add(new ContainerDataFile(file.getPath(), mimeType));
    return this;
  }

  public ContainerBuilder withDataFile(DataFile dataFile) {
    dataFiles.add(new ContainerDataFile(dataFile));
    return this;
  }

  public ContainerBuilder fromExistingFile(String filePath) {
    this.containerFilePath = filePath;
    return this;
  }

  public ContainerBuilder fromStream(InputStream containerInputStream) {
    this.containerInputStream = containerInputStream;
    return this;
  }

  public static <T extends Container> void setContainerImplementation(String containerType, Class<T> containerClass) {
    logger.info("Using " + containerClass.getName() + "for container type " + containerType);
    containerImplementations.put(containerType, containerClass);
  }

  private static boolean isCustomContainerType(String containerType) {
    return containerImplementations.containsKey(containerType);
  }

  public static void removeCustomContainerImplementations() {
    logger.info("Removing custom container implementations");
    containerImplementations.clear();
  }

  protected void addDataFilesToContainer(Container container) {
    for (ContainerDataFile file : dataFiles) {
      if (file.isStream) {
        container.addDataFile(file.inputStream, file.filePath, file.mimeType);
      } else if (file.isDataFile()) {
        container.addDataFile(file.dataFile);
      } else {
        container.addDataFile(file.filePath, file.mimeType);
      }
    }
  }

  protected boolean shouldOpenContainerFromFile() {
    return StringUtils.isNotBlank(containerFilePath);
  }

  protected boolean shouldOpenContainerFromStream() {
    return containerInputStream != null;
  }

  private class ContainerDataFile {

    String filePath;
    String mimeType;
    InputStream inputStream;
    DataFile dataFile;
    boolean isStream;

    public ContainerDataFile(String filePath, String mimeType) {
      this.filePath = filePath;
      this.mimeType = mimeType;
      isStream = false;
      validateDataFile();
    }

    public ContainerDataFile(InputStream inputStream, String filePath, String mimeType) {
      this.filePath = filePath;
      this.mimeType = mimeType;
      this.inputStream = inputStream;
      isStream = true;
      validateDataFile();
    }


    public ContainerDataFile(DataFile dataFile) {
      this.dataFile = dataFile;
      isStream = false;
    }

    public boolean isDataFile() {
      return dataFile != null;
    }

    private void validateDataFile() {
      if(StringUtils.isBlank(filePath)) {
        throw new InvalidDataFileException("File name/path cannot be empty");
      }
      if(StringUtils.isBlank(mimeType)) {
        throw new InvalidDataFileException("Mime type cannot be empty");
      }
    }
  }
}
