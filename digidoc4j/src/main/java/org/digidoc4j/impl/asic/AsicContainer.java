/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.AbstractContainerValidationResult;
import org.digidoc4j.impl.AbstractValidationResult;
import org.digidoc4j.impl.asic.asice.AsicEContainerValidator;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerValidator;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asics.AsicSContainerValidator;
import org.digidoc4j.impl.asic.asics.AsicSSignature;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.asic.xades.SignatureExtender;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by Andrei on 7.11.2017.
 */
public abstract class AsicContainer implements Container {

  private static final Logger LOGGER = LoggerFactory.getLogger(AsicContainer.class);

  protected Configuration configuration;
  protected DataFile timeStampToken;
  private List<DataFile> dataFiles = new ArrayList<>();
  private List<Signature> newSignatures = new ArrayList<>();
  private List<Signature> signatures = new ArrayList<>();
  private List<DataFile> newDataFiles = new ArrayList<>();
  private AsicParseResult containerParseResult;
  private boolean dataFilesHaveChanged;
  private String containerType = "";

  protected abstract String createUserAgent();

  /**
   * ASicContainer constructor
   */
  public AsicContainer() {
    this.configuration = Configuration.getInstance();
  }

  /**
   * ASicContainer constructor
   *
   * @param configuration configuration
   */
  public AsicContainer(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * ASicContainer constructor
   *
   * @param containerPath path
   * @param containerType type
   */
  public AsicContainer(String containerPath, String containerType) {
    this.configuration = Configuration.getInstance();
    this.containerType = containerType;
    this.openContainer(containerPath);
  }

  /**
   * ASicContainer constructor
   *
   * @param containerPath path
   * @param configuration configuration
   * @param containerType type
   */
  public AsicContainer(String containerPath, Configuration configuration, String containerType) {
    this.configuration = configuration;
    this.containerType = containerType;
    this.openContainer(containerPath);
  }

  /**
   * ASicContainer constructor
   *
   * @param stream        input stream
   * @param containerType type
   */
  public AsicContainer(InputStream stream, String containerType) {
    this.configuration = Configuration.getInstance();
    this.containerType = containerType;
    this.openContainer(stream);
  }

  /**
   * ASicContainer constructor
   *
   * @param stream        input stream
   * @param configuration configuration
   * @param containerType type
   */
  public AsicContainer(InputStream stream, Configuration configuration, String containerType) {
    this.configuration = configuration;
    this.containerType = containerType;
    this.openContainer(stream);
  }

  /**
   * ASicContainer constructor
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   * @param containerType container type
   */
  public AsicContainer(AsicParseResult containerParseResult, Configuration configuration, String containerType) {
    this.configuration = configuration;
    this.containerType = containerType;
    this.populateContainerWithParseResult(containerParseResult);
  }

  @Override
  public ContainerValidationResult validate() {
    ContainerValidationResult validationResult = this.validateContainer();
    if (validationResult instanceof AbstractValidationResult) {
      ((AbstractValidationResult) validationResult).print(this.configuration);
    }
    return validationResult;
  }

  protected ContainerValidationResult validateContainer() {
    ContainerValidationResult containerValidationResult;
    if (this.timeStampToken != null) {
      containerValidationResult = this.validateTimestampToken();
    } else {
      AsicEContainerValidator containerValidator;
      if (!this.isNewContainer()) {
        if (DocumentType.BDOC.name().equalsIgnoreCase(this.containerType)) {
          containerValidator = new BDocContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
        } else if (DocumentType.ASICS.name().equalsIgnoreCase(this.containerType)) {
          containerValidator = new AsicSContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
        } else {
          containerValidator = new AsicEContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
        }
      } else {
        if (DocumentType.BDOC.name().equalsIgnoreCase(this.containerType)) {
          containerValidator = new BDocContainerValidator(getConfiguration());
        } else if (DocumentType.ASICS.name().equalsIgnoreCase(this.containerType)) {
          containerValidator = new AsicSContainerValidator(getConfiguration());
        } else {
          containerValidator = new AsicEContainerValidator(getConfiguration());
        }
      }
      containerValidationResult = containerValidator.validate(getSignatures());
    }
    validateDataFiles(containerValidationResult);
    return containerValidationResult;
  }

  private ContainerValidationResult validateTimestampToken() {
    if (this.containerParseResult == null) {
      this.containerParseResult = new AsicStreamContainerParser(this.saveAsStream(), this.getConfiguration()).read();
    }
    return new TimeStampTokenValidator(this.containerParseResult).validate();
  }

  private void validateDataFiles(ContainerValidationResult containerValidationResult) {
    List<String> dataFilesValidationWarnings = dataFiles.stream()
            .filter(DataFile::isFileEmpty)
            .map(dataFile -> String.format("Data file '%s' is empty", dataFile.getName()))
            .collect(Collectors.toList());

    if (CollectionUtils.isEmpty(dataFilesValidationWarnings)) {
      return;
    }

    if (containerValidationResult instanceof AbstractContainerValidationResult) {
      AbstractContainerValidationResult abstractContainerValidationResult = (AbstractContainerValidationResult) containerValidationResult;
      List<DigiDoc4JException> exceptions = dataFilesValidationWarnings.stream().map(InvalidDataFileException::new).collect(Collectors.toList());
      abstractContainerValidationResult.addContainerWarnings(exceptions);
      abstractContainerValidationResult.addWarnings(exceptions);
    } else if (containerValidationResult instanceof AbstractValidationResult) {
      List<DigiDoc4JException> exceptions = dataFilesValidationWarnings.stream().map(InvalidDataFileException::new).collect(Collectors.toList());
      ((AbstractValidationResult) containerValidationResult).addWarnings(exceptions);
    } else {
      for (String dataFileValidationWarning : dataFilesValidationWarnings) {
        LOGGER.warn(dataFileValidationWarning);
      }
    }
  }

  @Override
  public File saveAsFile(String filePath) {
    LOGGER.debug("Saving container to file: " + filePath);
    File file = new File(filePath);
    try (OutputStream stream = Helper.bufferedOutputStream(file)) {
      save(stream);
      LOGGER.info("Container was saved to file " + filePath);
      return file;
    } catch (IOException e) {
      LOGGER.error("Unable to close stream: " + e.getMessage());
      throw new TechnicalException("Unable to close stream", e);
    }
  }

  @Override
  public Configuration getConfiguration() {
    return configuration;
  }

  private List<Signature> openSignatures(List<XadesSignatureWrapper> signatureWrappers) {
    List<Signature> signatures = new ArrayList<>(signatureWrappers.size());
    for (XadesSignatureWrapper signatureWrapper : signatureWrappers) {
      signatures.add(getSignatureOpener().open(signatureWrapper));
    }
    return signatures;
  }

  protected abstract AsicSignatureOpener getSignatureOpener();

  @Override
  public InputStream saveAsStream() {
    LOGGER.debug("Saving container as stream");
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    save(outputStream);
    InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    LOGGER.info("Container was saved to stream");
    return inputStream;
  }

  protected void validateIncomingSignature(Signature signature) {
    if (signature == null) {
      throw new TechnicalException("ValidateIncomingSignature is null");
    }
    if (!((signature instanceof BDocSignature) || (signature instanceof AsicSSignature) || (signature instanceof AsicESignature)
        || (signature instanceof AsicSignature))) {
      throw new TechnicalException("BDoc signature must be an instance of AsicSignature");
    }
  }

  protected List<Signature> extendAllSignatureProfile(SignatureProfile profile, List<Signature> signatures,
                                                      List<DataFile> dataFiles) {
    LOGGER.info("Extending all signatures' profile to " + profile.name());
    DetachedContentCreator detachedContentCreator = null;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    } catch (Exception e) {
      LOGGER.error("Error in datafiles processing: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
    List<DSSDocument> detachedContentList = detachedContentCreator.getDetachedContentList();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), detachedContentList);
    List<DSSDocument> extendedSignatureDocuments = signatureExtender.extend(signatures, profile);

    List<XadesSignatureWrapper> parsedSignatures = parseSignaturesWrappers(extendedSignatureDocuments, detachedContentList);
    List<Signature> extendedSignatures = openSignatures(parsedSignatures);
    LOGGER.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  private List<XadesSignatureWrapper> parseSignaturesWrappers(List<DSSDocument> signatureDocuments, List<DSSDocument> detachedContent) {
    AsicSignatureParser signatureParser = new AsicSignatureParser(detachedContent, configuration);
    List<XadesSignatureWrapper> parsedSignatures = new ArrayList<>();
    for (DSSDocument signatureDocument : signatureDocuments) {
      XadesSignature signature = signatureParser.parse(signatureDocument);
      parsedSignatures.add(new XadesSignatureWrapper(signature, signatureDocument));
    }
    return parsedSignatures;
  }

  protected void validateDataFilesRemoval() {
    if (isContainerSigned()) {
      LOGGER.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    }
  }

  protected void verifyDataFileIsNotEmpty(DataFile dataFile) {
    if (dataFile.isFileEmpty()) {
      String errorMessage = "Datafiles cannot be empty";
      LOGGER.error(errorMessage);
      throw new InvalidDataFileException(errorMessage);
    }
  }

  protected void verifyIfAllowedToAddDataFile(String fileName) {
    if (isContainerSigned()) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      LOGGER.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    checkForDuplicateDataFile(fileName);
  }

  private boolean isContainerSigned() {
    return !getSignatures().isEmpty();
  }

  private void checkForDuplicateDataFile(String fileName) {
    for (DataFile dataFile : getDataFiles()) {
      String dataFileName = dataFile.getName();
      if (StringUtils.equals(dataFileName, fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        LOGGER.error(errorMessage);
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  /**
   * @param containerType
   */

  public void setType(String containerType) {
    this.containerType = containerType;
  }

  @Override
  public String getType() {
    return containerType;
  }

  private void openContainer(String containerPath) {
    LOGGER.debug("Opening container from <{}>", containerPath);
    this.populateContainerWithParseResult(new AsicFileContainerParser(containerPath, this.getConfiguration()).read());
  }

  private void openContainer(InputStream inputStream) {
    LOGGER.debug("Opening container from stream");
    this.populateContainerWithParseResult(new AsicStreamContainerParser(inputStream, this.getConfiguration()).read());
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    this.containerParseResult = parseResult;
    this.dataFiles.addAll(parseResult.getDataFiles());
    this.timeStampToken = parseResult.getTimeStampToken();
    this.signatures.addAll(this.openSignatures(parseResult.getSignatures()));
  }

  private void removeExistingSignature(AsicSignature signature) {
    DSSDocument signatureDocument = signature.getSignatureDocument();
    if (signatureDocument == null) {
      return;
    }
    String signatureFileName = signatureDocument.getName();
    removeExistingSignatureFromContainer(signatureFileName);
    removeExistingFileFromContainer(signatureFileName);
  }

  private void removeExistingSignatureFromContainer(String signatureName) {
    LOGGER.debug("Removing signature '{}' from the container", signatureName);
    if (containerParseResult.removeSignature(signatureName)) {
      LOGGER.debug("Signature '{}' successfully removed from container", signatureName);
    }
  }

  private void removeExistingFileFromContainer(String fileName) {
    LOGGER.debug("Removing file '{}' from the container" + fileName);
    if (containerParseResult.removeAsicEntry(fileName)) {
      LOGGER.debug("File '{}' successfully removed from container", fileName);
    }
  }

  private void removeAllExistingSignaturesFromContainer() {
    LOGGER.debug("Removing all existing signatures");
    for (Signature signature : signatures) {
      removeExistingSignature((AsicSignature) signature);
    }
  }

  private int determineNextSignatureFileIndex() {
    Integer currentUsedSignatureFileIndex = containerParseResult.getCurrentUsedSignatureFileIndex();
    if (currentUsedSignatureFileIndex == null) {
      return 0;
    }
    return currentUsedSignatureFileIndex + 1;
  }

  @Override
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    DataFile dataFile = new DataFile(path, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream inputStream, String fileName, String mimeType) {
    DataFile dataFile = new DataFile(inputStream, fileName, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    DataFile dataFile = new DataFile(file.getPath(), mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    verifyDataFileIsNotEmpty(dataFile);
    String fileName = dataFile.getName();
    verifyIfAllowedToAddDataFile(fileName);
    if (Constant.ASICS_CONTAINER_TYPE.equals(getType())) {
      if (dataFiles.size() > 1) {
        throw new DigiDoc4JException("DataFile is already exists");
      } else if (newDataFiles.size() > 1) {
        throw new DigiDoc4JException("Not possible to add more than one datafile");
      }
    }
    dataFiles.add(dataFile);
    newDataFiles.add(dataFile);
    dataFilesHaveChanged = true;
    if (!isNewContainer()) {
      removeExistingFileFromContainer(AsicManifest.XML_PATH);
    }
  }

  @Override
  public void addSignature(Signature signature) {
    validateIncomingSignature(signature);
    validateSignatureId(signature);
    newSignatures.add(signature);
    signatures.add(signature);
  }

  /**
   * Set timestamp token to container
   *
   * @param timeStampToken
   */
  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    this.timeStampToken = timeStampToken;
  }

  private void validateSignatureId(Signature signature) {
    for (Signature sig : signatures) {
      if (sig.getId() != null && sig.getId().equalsIgnoreCase(signature.getId())) {
        throw new TechnicalException("Signature with Id \"" + signature.getId() + "\" already exists");
      }
    }
  }

  /**
   * Checks if timestamp token is defined
   *
   * @return {@code true} if timestamp token is defined, otherwise {@code false}
   *
   * @deprecated Deprecated for removal
   */
  @Deprecated
  public boolean isTimestampTokenDefined() {
    return timeStampToken != null;
  }

  //=======================================================

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    if (!isNewContainer()) {
      removeAllExistingSignaturesFromContainer();
      List<Signature> signatures = extendAllSignaturesProfile(profile, this.signatures, dataFiles);
      this.signatures = signatures;
      newSignatures = new ArrayList<>(signatures);
    } else {
      signatures = extendAllSignaturesProfile(profile, signatures, dataFiles);
    }
  }

  private List<Signature> extendAllSignaturesProfile(SignatureProfile profile, List<Signature> signatures,
                                                     List<DataFile> dataFiles) {
    List<Signature> extendedSignatures;
    if (Constant.ASICS_CONTAINER_TYPE.equals(getType())) {
      extendedSignatures = extendAllSignatureProfile(profile, signatures, Arrays.asList(dataFiles.get(0)));
    } else {
      extendedSignatures = extendAllSignatureProfile(profile, signatures, dataFiles);
    }
    return extendedSignatures;
  }

  @Override
  public void removeSignature(Signature signature) {
    if (signature == null) {
      LOGGER.warn("Cannot remove null signature");
      return;
    }

    LOGGER.info("Removing signature " + signature.getId());
    if (!signatures.contains(signature)) {
      throw new SignatureNotFoundException("Signature not found: " + signature.getId());
    }

    if (!isNewContainer()) {
      validateIncomingSignature(signature);
      boolean wasNewlyAddedSignature = newSignatures.remove(signature);
      boolean wasIncludedInContainer = signatures.remove(signature);
      if (wasIncludedInContainer && !wasNewlyAddedSignature) {
        LOGGER.debug("This signature was included in the container before the container was opened");
        removeExistingSignature((AsicSignature) signature);
      }
    } else {
      newSignatures.remove(signature);
      signatures.remove(signature);
    }
  }

  @Override
  public void removeDataFile(DataFile file) {
    validateDataFilesRemoval();

    boolean wasRemovalSuccessful = removeDataFileFromContainer(file);
    if (!wasRemovalSuccessful) {
      throw new DataFileNotFoundException(file.getName());
    }
    dataFilesHaveChanged = true;
    if (!isNewContainer()) {
      removeExistingFileFromContainer(AsicManifest.XML_PATH);
    }
    LOGGER.info("Data file named '{}' has been removed", file.getName());
  }

  private boolean removeDataFileFromContainer(DataFile dataFile) {
    if (!isNewContainer()) {
      removeExistingFileFromContainer(dataFile.getName());
      containerParseResult.getDataFiles().remove(dataFile);
      containerParseResult.getDetachedContents().remove(dataFile.getDocument());
    }
    newDataFiles.remove(dataFile);
    return dataFiles.remove(dataFile);
  }

  private boolean isNewContainer() {
    return containerParseResult == null;
  }

  @Override
  public List<Signature> getSignatures() {
    return signatures;
  }

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = createUserAgent();
    zipCreator.setZipComment(userAgent);
    if (!isNewContainer()) {
      int nextSignatureFileIndex = determineNextSignatureFileIndex();
      zipCreator.writeExistingEntries(containerParseResult.getAsicEntries());
      if (dataFilesHaveChanged) {
        zipCreator.writeManifest(dataFiles, getType());
      }
      zipCreator.writeSignatures(newSignatures, nextSignatureFileIndex);
      zipCreator.writeDataFiles(newDataFiles);
      if (StringUtils.isNotBlank(containerParseResult.getZipFileComment())) {
        zipCreator.writeContainerComment(containerParseResult.getZipFileComment());
      }
    } else {
      int startingSignatureFileIndex = 0;
      zipCreator.writeAsiceMimeType(getType());
      zipCreator.writeManifest(dataFiles, getType());
      zipCreator.writeDataFiles(dataFiles);
      if (timeStampToken != null && Constant.ASICS_CONTAINER_TYPE.equals(getType())) {
        zipCreator.writeTimestampToken(timeStampToken);
      } else {
        zipCreator.writeSignatures(signatures, startingSignatureFileIndex);
      }
      zipCreator.writeContainerComment(userAgent);
    }
    zipCreator.finalizeZipFile();
  }

  public AsicParseResult getContainerParseResult() {
    return containerParseResult;
  }
}
