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

import eu.europa.esig.dss.DigestAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.CustomContainerBuilder;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.AsicEContainerBuilder;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.asics.AsicSContainerBuilder;
import org.digidoc4j.impl.ddoc.DDocContainerBuilder;
import org.digidoc4j.impl.pades.PadesContainerBuilder;
import org.digidoc4j.signers.TimestampToken;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class for creating and opening containers.
 * <p>
 *   Here's an example of creating a new container:
 * </p>
 * <p><code>
 *   {@link Container} container = {@link ContainerBuilder}. <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#aContainer(String) aContainer("BDOC")}. <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#withConfiguration(Configuration) withConfiguration(configuration)}.  // Configuration settings <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#withDataFile(String, String) withDataFile("testFiles/legal_contract_1.txt", "text/plain")}.  // Adding a document from a hard drive <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#withDataFile(InputStream, String, String) withDataFile(inputStream, "legal_contract_2.txt", "text/plain")}.  // Adding a document from a stream <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#withTimeStampToken(DigestAlgorithm digestAlgorithm)}.  // Adding timestamp token in case of ASICS <br/>
 *   &nbsp;&nbsp; {@link ContainerBuilder#build() build()}; <br/>
 * </code></p>
 * <p>
 *   Use {@link ContainerBuilder#aContainer() ContainerBuilder.aContainer()} to create a new container builder, populate the builder with data and
 *   finally call {@link ContainerBuilder#build()} to create the container with the populated data.
 *   Use {@link ContainerBuilder#fromExistingFile(String)} or {@link ContainerBuilder#fromStream(InputStream)} to open an existing container.
 * </p>
 */
public abstract class ContainerBuilder {

  private static final Logger logger = LoggerFactory.getLogger(ContainerBuilder.class);

  protected static Map<String, Class<? extends Container>> containerImplementations = new HashMap<>();
  protected Configuration configuration;
  protected List<ContainerDataFile> dataFiles = new ArrayList<>();
  protected String containerFilePath;
  protected InputStream containerInputStream;
  protected static String containerType;
  private DataFile timeStampToken;

  /**
   * Create a new BDoc container builder.
   *
   * @return builder for creating or opening a BDOC(ASICE) container.
   */
  public static ContainerBuilder aContainer() {
    return aContainer(Container.DocumentType.BDOC);
  }

  /**
   * Create a new container builder based on a container type.
   *
   * @param type a type of container to be created, e.g. "BDOC(ASICE)", "ASICS" or "DDOC".
   *
   * @return builder for creating a container.
   */
  public static ContainerBuilder aContainer(String type) {
    ContainerBuilder.containerType = type;
    if (ContainerBuilder.isCustomContainerType(type)) {
      return new CustomContainerBuilder(type);
    } else {
      try {
        return ContainerBuilder.aContainer(Container.DocumentType.valueOf(type));
      } catch (IllegalArgumentException e) {
        throw new NotSupportedException(String.format("Container type <%s> is unsupported", type));
      }
    }
  }

  /**
   * Create a new container builder based on a container type.
   *
   * @param type a type of container to be created, e.g. "BDOC(ASICE)", "ASICS" or "DDOC".
   *
   * @return builder for creating a container.
   */
  public static ContainerBuilder aContainer(Container.DocumentType type) {
    ContainerBuilder.containerType = type.name();
    if (ContainerBuilder.isCustomContainerType(ContainerBuilder.containerType)) {
      return new CustomContainerBuilder(ContainerBuilder.containerType);
    } else {
      switch (type) {
        case BDOC:
          return new BDocContainerBuilder();
        case DDOC:
          return new DDocContainerBuilder();
        case ASICS:
          return new AsicSContainerBuilder();
        case ASICE:
          return new AsicEContainerBuilder();
        case PADES:
          return new PadesContainerBuilder();
      }
    }
    throw new NotSupportedException(String.format("Container type <%s> is unsupported", type));
  }

  /**
   * Builds a new container or opens existing container from the parameters given to the builder.
   *
   * @return fresh container.
   */
  public Container build() {
    if (shouldOpenContainerFromFile()) {
      return overrideContainerIfNeeded(openContainerFromFile());
    } else if (shouldOpenContainerFromStream()) {
      return overrideContainerIfNeeded(openContainerFromStream());
    }
    Container container = createNewContainer();
    addDataFilesToContainer(container);
    if (timeStampToken != null){
      addTimeStampTokenToContainer(container);
    }
    return container;
  }

  /**
   * Specify configuration for the container.
   *
   * @param configuration configuration to use for creating the container.
   * @return builder for creating or opening a container.
   */
  public ContainerBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  /**
   * Add a data file to the container.
   *
   * @param filePath data file location on the disk.
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @return builder for creating or opening a container.
   * @throws InvalidDataFileException
   */
  public ContainerBuilder withDataFile(String filePath, String mimeType) throws InvalidDataFileException {
    if (Constant.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
        && !dataFiles.isEmpty()){
      throw new DigiDoc4JException("Cannot add second file in case of ASICS container");
    }
    dataFiles.add(new ContainerDataFile(filePath, mimeType));
    return this;
  }

  /**
   * Add a data file from a stream to the container.
   *
   * @param inputStream stream of a data file to be added to the container.
   * @param fileName name of the data file to be added.
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @return builder for creating or opening a container.
   * @throws InvalidDataFileException
   */
  public ContainerBuilder withDataFile(InputStream inputStream, String fileName, String mimeType) throws InvalidDataFileException {
    if (Constant.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
        && !dataFiles.isEmpty()){
      throw new DigiDoc4JException("Cannot add second file in case of ASICS container");
    }
    dataFiles.add(new ContainerDataFile(inputStream, fileName, mimeType));
    return this;
  }

  /**
   * Add a data file to the container.
   *
   * @param file data file to be added to the container.
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @return builder for creating or opening a container.
   * @throws InvalidDataFileException
   */
  public ContainerBuilder withDataFile(File file, String mimeType) throws InvalidDataFileException {
    if (Constant.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
        && !dataFiles.isEmpty()){
      throw new DigiDoc4JException("Cannot add second file in case of ASICS container");
    }
    dataFiles.add(new ContainerDataFile(file.getPath(), mimeType));
    return this;
  }

  /**
   * Add a data file to the container.
   *
   * @param dataFile data file to be added to the container.
   * @return builder for creating or opening a container.
   */
  public ContainerBuilder withDataFile(DataFile dataFile) {
    if (Constant.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
        && !dataFiles.isEmpty()){
      throw new DigiDoc4JException("Cannot add second file in case of ASICS container");
    }
    dataFiles.add(new ContainerDataFile(dataFile));
    return this;
  }

  /**
   * Add time stamp token to container
   *
   * @param digestAlgorithm
   * @return ContainerBuilder
   */
  public ContainerBuilder withTimeStampToken(DigestAlgorithm digestAlgorithm){
    timeStampToken = TimestampToken.generateTimestampToken(digestAlgorithm, dataFiles, configuration);
    return this;
  }

  /**
   * Open container from an existing file.
   *
   * @param filePath absolute path to the container file.
   * @return builder for creating or opening a container.
   */
  public ContainerBuilder fromExistingFile(String filePath) {
    this.containerFilePath = filePath;
    return this;
  }

  /**
   * Open container from a stream.
   *
   * @param containerInputStream stream of the container file to be opened.
   * @return builder for creating or opening a container.
   */
  public ContainerBuilder fromStream(InputStream containerInputStream) {
    this.containerInputStream = containerInputStream;
    return this;
  }

  /**
   * Set a custom container implementation class to be used for the container type.
   *
   * @param containerType container type name used when handling such containers.
   * @param containerClass container implementation for handling such container types.
   * @param <T> container class extending the Container interface.
   * @see Container
   */
  public static <T extends Container> void setContainerImplementation(String containerType, Class<T> containerClass) {
    logger.info("Using <{}> for container type <{}>", containerClass.getName(), containerType);
    containerImplementations.put(containerType, containerClass);
  }

  /**
   * Clear the list of custom container implementations and types
   * and continue using the default container types and implementations.
   */
  public static void removeCustomContainerImplementations() {
    logger.info("Removing custom container implementations");
    containerImplementations.clear();
  }

  protected abstract Container createNewContainer();

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

  private void addTimeStampTokenToContainer(Container container) {
    container.setTimeStampToken(timeStampToken);
  }

  protected boolean shouldOpenContainerFromFile() {
    return StringUtils.isNotBlank(containerFilePath);
  }

  protected boolean shouldOpenContainerFromStream() {
    return containerInputStream != null;
  }

  public abstract ContainerBuilder usingTempDirectory(String temporaryDirectoryPath);

  private static boolean isCustomContainerType(String containerType) {
    return containerImplementations.containsKey(containerType);
  }

  public class ContainerDataFile {

    public String filePath;
    String mimeType;
    public InputStream inputStream;
    DataFile dataFile;
    public boolean isStream;

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
      validateFileName();
    }

    public ContainerDataFile(DataFile dataFile) {
      this.dataFile = dataFile;
      isStream = false;
    }

    public boolean isDataFile() {
      return dataFile != null;
    }

    private void validateDataFile() {
      if (StringUtils.isBlank(filePath)) {
        throw new InvalidDataFileException("File name/path cannot be empty");
      }
      if (StringUtils.isBlank(mimeType)) {
        throw new InvalidDataFileException("Mime type cannot be empty");
      }
    }

    private void validateFileName() {
      if (Helper.hasSpecialCharacters(filePath)) {
        throw new InvalidDataFileException("File name " + filePath
            + " must not contain special characters like: "
            + Helper.SPECIAL_CHARACTERS);
      }
    }
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
    if (container instanceof AsicContainer && container.getSignatures().isEmpty()) {
      return overrideContainerIfDifferentType((AsicContainer) container);
    } else {
      return container;
    }
  }

  private Container overrideContainerIfDifferentType(AsicContainer container) {
    if (containerType.equalsIgnoreCase(container.getType())) {
      return container;
    } else {
      AsicParseResult containerParseResult = container.getContainerParseResult();
      Configuration configuration = container.getConfiguration();

      if (containerType.equals(Container.DocumentType.BDOC.name())) {
        return new BDocContainer(containerParseResult, configuration);
      } else if (containerType.equals(Container.DocumentType.ASICE.name())) {
        return new AsicEContainer(containerParseResult, configuration);
      } else {
        return container;
      }
    }
  }
}
