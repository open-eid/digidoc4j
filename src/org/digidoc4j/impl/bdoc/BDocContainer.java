/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.AsicContainerParser;
import org.digidoc4j.impl.bdoc.asic.AsicParseResult;
import org.digidoc4j.impl.bdoc.asic.BDocContainerValidator;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class BDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainer.class);
  private List<Signature> signatures = new ArrayList<>();
  private List<DataFile> dataFiles = new ArrayList<>();
  private Configuration configuration;
  private ValidationResult validationResult;
  private AsicParseResult containerParseResult;


  public BDocContainer() {
    logger.debug("Instantiating BDoc container");
    configuration = new Configuration();
  }

  public BDocContainer(Configuration configuration) {
    logger.debug("Instantiating BDoc container with configuration");
    this.configuration = configuration;
  }

  public BDocContainer(String containerPath) {
    this(containerPath, new Configuration());
  }

  public BDocContainer(String containerPath, Configuration configuration) {
    logger.debug("Opening container from " + containerPath);
    this.configuration = configuration;
    openContainer(containerPath);
  }

  public BDocContainer(InputStream stream) {
    this(stream, new Configuration());
  }

  public BDocContainer(InputStream stream, Configuration configuration) {
    logger.debug("Opening container from stream");
    this.configuration = configuration;
    openContainer(stream);
  }

  private void openContainer(String containerPath) {
    containerParseResult = new AsicContainerParser(containerPath).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void openContainer(InputStream inputStream) {
    containerParseResult = new AsicContainerParser(inputStream).read();
    populateContainerWithParseResult(containerParseResult);
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    dataFiles = parseResult.getDataFiles();
    List<DSSDocument> signatureFiles = parseResult.getSignatures();
    List<DSSDocument> detachedContents = parseResult.getDetachedContents();
    parseSignatureFiles(signatureFiles, detachedContents);
  }

  private void parseSignatureFiles(List<DSSDocument> signatureFiles, List<DSSDocument> detachedContents) {
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    for(DSSDocument signatureFile: signatureFiles) {
      List<BDocSignature> bDocSignatures = signatureOpener.parse(signatureFile);
      signatures.addAll(bDocSignatures);
    }
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    String fileName = new File(path).getName();
    verifyIfAllowedToAddDataFile(fileName);
    DataFile dataFile = new DataFile(path, mimeType);
    dataFiles.add(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream inputStream, String fileName, String mimeType) {
    fileName = new File(fileName).getName();
    verifyIfAllowedToAddDataFile(fileName);
    DataFile dataFile = new DataFile(inputStream, fileName, mimeType);
    dataFiles.add(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    verifyIfAllowedToAddDataFile(file.getName());
    DataFile dataFile = new DataFile(file.getPath(), mimeType);
    dataFiles.add(dataFile);
    return dataFile;
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    verifyIfAllowedToAddDataFile(dataFile.getName());
    dataFiles.add(dataFile);
  }

  @Override
  public void addSignature(Signature signature) {
    if(!(signature instanceof BDocSignature)) {
      throw new TechnicalException("BDoc signature must be an instance of BDocSignature");
    }
    signatures.add(signature);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  @Override
  @Deprecated
  public DataFile getDataFile(int index) {
    return getDataFiles().get(index);
  }

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public List<Signature> getSignatures() {
    return signatures;
  }

  @Override
  @Deprecated
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  @Override
  public void removeDataFile(DataFile file) {
    logger.info("Removing data file: " + file.getName());
    validateDataFilesRemoval();
    boolean wasRemovalSuccessful = dataFiles.remove(file);

    if(!wasRemovalSuccessful) {
      throwDataFileNotFoundException(file.getName());
    }
  }

  @Override
  @Deprecated
  public void removeDataFile(String fileName) {
    logger.info("Removing data file: " + fileName);
    validateDataFilesRemoval();

    for(DataFile dataFile: dataFiles) {
      String name = dataFile.getName();
      if(StringUtils.equals(fileName, name)) {
        dataFiles.remove(dataFile);
        logger.debug("Data file has been removed");
        return;
      }
    }

    throwDataFileNotFoundException(fileName);
  }

  @Override
  public void removeSignature(Signature signature) {
    signatures.remove(signature);
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    signatures.remove(signatureId);
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    logger.info("Extending all signatures' profile to " + profile.name());
    validatePossibilityToExtendTo(profile);
    List<DSSDocument> signaturesToExtend = containerParseResult.getSignatures();
    DSSDocument detachedContent = containerParseResult.getDetachedContent();
    SignatureExtender signatureExtender = new SignatureExtender(configuration, detachedContent);
    List<DSSDocument> extendedSignatures = signatureExtender.extend(signaturesToExtend, profile);
    this.signatures.clear();
    parseSignatureFiles(extendedSignatures, containerParseResult.getDetachedContents());
  }

  @Override
  public File saveAsFile(String filePath) {
    logger.info("Saving container to file: " + filePath);
    File file = new File(filePath);
    AsicContainerCreator zipCreator = new AsicContainerCreator(file);
    writeAsicContainer(zipCreator);
    return file;
  }

  @Override
  public InputStream saveAsStream() {
    AsicContainerCreator zipCreator = new AsicContainerCreator();
    writeAsicContainer(zipCreator);
    return zipCreator.fetchInputStreamOfFinalizedContainer();
  }

  @Override
  @Deprecated
  public void save(String path) {
    saveAsFile(path);
  }

  @Override
  @Deprecated
  public void save(OutputStream out) {
    try {
      InputStream inputStream = saveAsStream();
      IOUtils.copy(inputStream, out);
    } catch (IOException e) {
      logger.error("Error saving container input stream to output stream: " + e.getMessage());
      throw new TechnicalException("Error saving container input stream to output stream", e);
    }
  }

  @Override
  public ValidationResult validate() {
    if(validationResult == null) {
      validationResult = new BDocContainerValidator(signatures, containerParseResult).validate();
    }
    return validationResult;
  }

  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    return null;
  }

  @Override
  @Deprecated
  public String getSignatureProfile() {
    return null;
  }

  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {

  }

  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    return null;
  }

  @Override
  @Deprecated
  public void addRawSignature(byte[] signature) {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  @Deprecated
  public void addRawSignature(InputStream signatureStream) {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  @Deprecated
  public int countDataFiles() {
    return getDataFiles().size();
  }

  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    return null;
  }

  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    return null;
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
    return null;
  }

  @Override
  @Deprecated
  public void extendTo(SignatureProfile profile) {
    extendSignatureProfile(profile);
  }

  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {

  }

  public Configuration getConfiguration() {
    return configuration;
  }

  private void validateDataFilesRemoval() {
    if(!signatures.isEmpty()) {
      logger.error("Datafiles cannot be removed from an already signed container");
      throw new DigiDoc4JException("Datafiles cannot be removed from an already signed container");
    }
  }

  private void throwDataFileNotFoundException(String fileName) {
    DigiDoc4JException exception = new DigiDoc4JException("File not found: " + fileName);
    logger.error(exception.getMessage());
    throw exception;
  }

  private void verifyIfAllowedToAddDataFile(String fileName) {
    if (signatures.size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }

    checkForDuplicateDataFile(fileName);
  }

  private void checkForDuplicateDataFile(String fileName) {
    logger.debug("");
    for (DataFile dataFile : dataFiles) {
      String dataFileName = dataFile.getName();
      if (StringUtils.equals(dataFileName, fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        logger.error(errorMessage);
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  private void writeAsicContainer(AsicContainerCreator zipCreator) {
    zipCreator.writeAsiceMimeType();
    zipCreator.writeManifest(dataFiles);
    zipCreator.writeDataFiles(dataFiles);
    zipCreator.writeSignatures(signatures);
    zipCreator.finalizeZipFile();
  }

  private void validatePossibilityToExtendTo(SignatureProfile profile) {
    logger.debug("Validating if it's possible to extend all the signatures to " + profile);
    for(Signature signature: signatures) {
      if (profile == signature.getProfile()) {
        String errorMessage = "It is not possible to extend the signature to the same level";
        logger.error(errorMessage);
        throw new DigiDoc4JException(errorMessage);
      }
    }
  }
}
