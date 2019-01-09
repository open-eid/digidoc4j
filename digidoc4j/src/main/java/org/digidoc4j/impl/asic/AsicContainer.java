package org.digidoc4j.impl.asic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.AbstractValidationResult;
import org.digidoc4j.impl.asic.asice.AsicEContainerValidator;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerValidator;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asics.AsicSSignature;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.asic.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

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
  private ContainerValidationResult validationResult;
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

  @Override
  public ContainerValidationResult validate() {
    if (this.validationResult == null) {
      this.validationResult = this.validateContainer();
    }
    if (this.validationResult instanceof AbstractValidationResult) {
      ((AbstractValidationResult) this.validationResult).print(this.configuration);
    }
    return this.validationResult;
  }

  protected ContainerValidationResult validateContainer() {
    if (this.timeStampToken != null) {
      return this.validateTimestampToken();
    } else {
      if (!this.isNewContainer()) {
        if (DocumentType.BDOC.toString().equals(this.containerType)) {
          return new BDocContainerValidator(this.containerParseResult, this.getConfiguration(),
              !this.dataFilesHaveChanged).validate(this.getSignatures());
        } else {
          return new AsicEContainerValidator(this.containerParseResult, this.getConfiguration(),
              !this.dataFilesHaveChanged).validate(this.getSignatures());
        }
      } else {
        if (DocumentType.BDOC.toString().equals(this.containerType)) {
          return new BDocContainerValidator(this.getConfiguration()).validate(this.getSignatures());
        } else {
          return new AsicEContainerValidator(this.getConfiguration()).validate(this.getSignatures());
        }
      }
    }
  }

  private ContainerValidationResult validateTimestampToken() {
    if (this.containerParseResult == null) {
      this.containerParseResult = new AsicStreamContainerParser(this.saveAsStream(), this.getConfiguration()).read();
    }
    return new TimeStampTokenValidator(this.containerParseResult).validate();
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

  protected abstract List<Signature> parseSignatureFiles(List<DSSDocument> signatureFiles,
                                                         List<DSSDocument> detachedContents);

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
    List<Signature> extendedSignatures = parseSignatureFiles(extendedSignatureDocuments, detachedContentList);
    LOGGER.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  protected void validateDataFilesRemoval() {
    if (!getSignatures().isEmpty()) {
      LOGGER.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    }
  }

  protected void verifyIfAllowedToAddDataFile(String fileName) {
    if (getSignatures().size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      LOGGER.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    checkForDuplicateDataFile(fileName);
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
    this.signatures.addAll(this.parseSignatureFiles(parseResult.getSignatures(), parseResult.getDetachedContents()));
  }

  private void removeExistingSignature(BDocSignature signature) {
    DSSDocument signatureDocument = signature.getSignatureDocument();
    if (signatureDocument == null) {
      return;
    }
    String signatureFileName = signatureDocument.getName();
    removeExistingFileFromContainer(signatureFileName);
  }

  private void removeExistingFileFromContainer(String filePath) {
    LOGGER.debug("Removing file from the container: " + filePath);
    if (containerParseResult != null) {
      List<AsicEntry> asicEntries = containerParseResult.getAsicEntries();
      for (AsicEntry entry : asicEntries) {
        String entryFileName = entry.getZipEntry().getName();
        if (StringUtils.equalsIgnoreCase(filePath, entryFileName)) {
          asicEntries.remove(entry);
          LOGGER.debug("File was successfully removed");
          break;
        }
      }
    }
  }

  private void removeAllExistingSignaturesFromContainer() {
    LOGGER.debug("Removing all existing signatures");
    for (Signature signature : signatures) {
      removeExistingSignature((BDocSignature) signature);
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
    removeExistingFileFromContainer(AsicManifest.XML_PATH);
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

  private byte[] getDigest() {
    DataFile dataFile = getDataFiles().get(0);
    return dataFile.getBytes();
  }

  /**
   * Controlls if timestamp token is defined
   *
   * @return true if timestemp token defined
   */
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
    LOGGER.info("Removing signature " + signature.getId());
    if (!isNewContainer()) {
      validateIncomingSignature(signature);
      boolean wasNewlyAddedSignature = newSignatures.remove(signature);
      boolean wasIncludedInContainer = signatures.remove(signature);
      if (wasIncludedInContainer && !wasNewlyAddedSignature) {
        LOGGER.debug("This signature was included in the container before the container was opened");
        removeExistingSignature((BDocSignature) signature);
      }
    } else {
      signatures.remove(signature);
    }
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    LOGGER.debug("Removing signature from index " + signatureId);
    if (!isNewContainer()) {
      Signature signature = signatures.get(signatureId);
      if (signature != null) {
        removeSignature(signature);
      }
    } else {
      signatures.remove(signatureId);
    }

  }

  @Override
  public void removeDataFile(String fileName) {
    if (!isNewContainer()) {
      LOGGER.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else {
      LOGGER.info("Removing data file: " + fileName);
      validateDataFilesRemoval();

      for (DataFile dataFile : dataFiles) {
        String name = dataFile.getName();
        if (StringUtils.equals(fileName, name)) {
          dataFiles.remove(dataFile);
          LOGGER.debug("Data file has been removed");
          return;
        }
      }
      throw new DataFileNotFoundException(fileName);
    }
  }

  @Override
  public void removeDataFile(DataFile file) {
    if (!isNewContainer()) {
      LOGGER.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    } else {
      LOGGER.info("Removing data file: " + file.getName());
      validateDataFilesRemoval();
      boolean wasRemovalSuccessful = dataFiles.remove(file);

      if (!wasRemovalSuccessful) {
        throw new DataFileNotFoundException(file.getName());
      }
    }
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

  //=============== Deprecated methods ====================

  @Override
  @Deprecated
  public void addRawSignature(byte[] signatureDocument) {
    LOGGER.info("Adding raw signature");
    Signature signature = SignatureBuilder.
        aSignature(this).
        openAdESSignature(signatureDocument);
    addSignature(signature);
  }

  @Override
  @Deprecated
  public void addRawSignature(InputStream signatureStream) {
    try {
      byte[] bytes = IOUtils.toByteArray(signatureStream);
      addRawSignature(bytes);
    } catch (IOException e) {
      LOGGER.error("Failed to read signature stream: " + e.getMessage());
      throw new InvalidSignatureException();
    }
  }

  @Override
  @Deprecated
  public int countDataFiles() {
    return getDataFiles().size();
  }

  @Override
  @Deprecated
  public int countSignatures() {
    return getSignatures().size();
  }

  @Override
  @Deprecated
  public DocumentType getDocumentType() {
    return Container.DocumentType.BDOC;
  }

  @Override
  @Deprecated
  public String getVersion() {
    return "";
  }

  @Override
  @Deprecated
  public void extendTo(SignatureProfile profile) {
    extendSignatureProfile(profile);
  }

  @Override
  @Deprecated
  public void save(String path) {
    saveAsFile(path);
  }

  @Override
  @Deprecated
  public DataFile getDataFile(int index) {
    return getDataFiles().get(index);
  }

  @Override
  @Deprecated
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  /**
   * Prepare signing method is not supported by ASiC container.
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return NotSupportedException
   */

  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotSupportedException("Prepare signing method is not supported by Asic container");
  }

  /**
   * Getting signature profile method is not supported by ASiC container.
   *
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public String getSignatureProfile() {
    throw new NotSupportedException("Getting signature profile method is not supported by Asic container");
  }

  /**
   * Setting signature parameters method is not supported by ASiC container
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   */
  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotSupportedException("Setting signature parameters method is not supported by Asic container");
  }

  /**
   * Getting digest algorithm method is not supported by ASiC container.
   *
   * @return NotSupportedException.
   */
  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    throw new NotSupportedException("Getting digest algorithm method is not supported by Asic container");
  }

  /**
   * Sign method is not supported by ASiC container.
   *
   * @param signatureToken signatureToken implementation
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    throw new NotSupportedException("Sign method is not supported by Asic container");
  }

  /**
   * Sign raw method is not supported by ASiC container.
   *
   * @param rawSignature raw signature
   * @return NotSupportedException
   */
  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    throw new NotSupportedException("Sign raw method is not supported by Asic container");
  }

  /**
   * Setting signature profile method is not supported by ASiC container.
   *
   * @param profile signature profile
   */
  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Setting signature profile method is not supported by Asic container");
  }
}
