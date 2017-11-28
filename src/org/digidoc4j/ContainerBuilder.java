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
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.CustomContainerBuilder;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.impl.bdoc.asic.AsicEContainerBuilder;
import org.digidoc4j.impl.bdoc.asic.AsicSContainerBuilder;
import org.digidoc4j.impl.ddoc.DDocContainerBuilder;
import org.digidoc4j.impl.pades.PadesContainerBuilder;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

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

  public static final String BDOC_CONTAINER_TYPE = "BDOC";
  public static final String DDOC_CONTAINER_TYPE = "DDOC";
  public static final String ASICS_CONTAINER_TYPE = "ASICS";
  public static final String PADES_CONTAINER_TYPE = "PADES";
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
    return aContainer(BDOC_CONTAINER_TYPE);
  }

  /**
   * Create a new container builder based on a container type.
   *
   * @param containerType a type of container to be created, e.g. "BDOC(ASICE)" , "ASICS" or "DDOC".
   *
   * @return builder for creating a container.
   */
  public static ContainerBuilder aContainer(String containerType) {
    ContainerBuilder.containerType = containerType;
    if (isCustomContainerType(containerType)) {
      return new CustomContainerBuilder(containerType);
    }
    switch (containerType) {
      case BDOC_CONTAINER_TYPE:
        return new AsicEContainerBuilder();
      case DDOC_CONTAINER_TYPE:
        return new DDocContainerBuilder();
      case ASICS_CONTAINER_TYPE:
        return new AsicSContainerBuilder();
      case PADES_CONTAINER_TYPE:
        return new PadesContainerBuilder();
    }
    throw new NotSupportedException("Container type is not supported: " + containerType);
  }

  /**
   * Builds a new container or opens existing container from the parameters given to the builder.
   *
   * @return fresh container.
   */
  public Container build() {
    if (shouldOpenContainerFromFile()) {
      return openContainerFromFile();
    } else if (shouldOpenContainerFromStream()) {
      return openContainerFromStream();
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
    if (ContainerBuilder.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
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
    if (ContainerBuilder.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
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
    if (ContainerBuilder.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
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
    if (ContainerBuilder.ASICS_CONTAINER_TYPE.equals(ContainerBuilder.containerType)
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
    if (dataFiles.isEmpty()){
      throw new DigiDoc4JException("Add data file first");
    }
    if (dataFiles.size() > 1){
      throw new DigiDoc4JException("Supports only asics with only one datafile");
    }
    ContainerBuilder.ContainerDataFile containerDataFile = dataFiles.get(0);

    OnlineTSPSource onlineTSPSource = new OnlineTSPSource();
    if (configuration == null){
      configuration = Configuration.getInstance();
    }
    onlineTSPSource.setTspServer(configuration.getTspSource());

    SkDataLoader dataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    dataLoader.setAsicSUserAgentSignatureProfile();
    onlineTSPSource.setDataLoader(dataLoader);


    try {
      byte[] dataFielDigest;
      if (!containerDataFile.isStream){
        Path path = Paths.get(containerDataFile.filePath);
        dataFielDigest = Files.readAllBytes(path);
      } else{
          dataFielDigest = IOUtils.toByteArray(containerDataFile.inputStream);
      }
      byte[] digest = DSSUtils.digest(digestAlgorithm, dataFielDigest);
      TimeStampToken timeStampResponse = onlineTSPSource.getTimeStampResponse(digestAlgorithm, digest);
      String timestampFilename = "timestamp";
      timeStampToken = new DataFile();
      timeStampToken.setDocument(new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST));
      timeStampToken.setMediaType(MimeType.TST.getMimeTypeString());
    } catch (IOException e) {
      e.printStackTrace();
    }

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
    logger.info("Using " + containerClass.getName() + "for container type " + containerType);
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

  protected abstract Container openContainerFromFile();

  protected abstract Container openContainerFromStream();

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
}
