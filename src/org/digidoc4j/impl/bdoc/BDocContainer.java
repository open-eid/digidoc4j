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

import javax.crypto.SecretKey;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.CryptoFilesContainer;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureFilesContainer;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.impl.bdoc.asic.BDocContainerValidator;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.digidoc4j.impl.bdoc.xades.SignatureExtender;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public class BDocContainer implements Container, SignatureFilesContainer, CryptoFilesContainer {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainer.class);
  private Configuration configuration;
  private ValidationResult validationResult;

  private List<Signature> signatures = new ArrayList<>();
  private List<DataFile> dataFiles = new ArrayList<>();
  protected BDocCrypto bDocCrypto = new BDocCrypto(this);

  public BDocContainer() {
    logger.debug("Instantiating BDoc container");
    configuration = Configuration.getInstance();
  }

  public BDocContainer(Configuration configuration) {
    logger.debug("Instantiating BDoc container with configuration");
    this.configuration = configuration;
  }

  //#region public DataFile addDataFile(...)
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
    verifyIfAllowedToAddDataFile(dataFile.getName());
    getDataFiles().add(dataFile);
  }
  //#endregion public DataFile addDataFile(...)

  @Override
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  @Override
  public List<DataFile> getPlainDataFiles() {
    return bDocCrypto.getPlainDataFiles();
  }

  @Override
  public void setEncryptionKey(SecretKey key) {
    bDocCrypto.setEncryptionKey(key);
  }

  @Override
  public void setEncryptionKey(byte[] keyBytes) {
    bDocCrypto.setEncryptionKey(keyBytes);
  }

  @Override
  public void generateEncryptionKey() {
    bDocCrypto.generateEncryptionKey();
  }

  @Override
  public void generateEncryptionKey(String algorithmW3cURI) {
    bDocCrypto.generateEncryptionKey(algorithmW3cURI);
  }

  @Override
  public EncryptedDataFile encryptDataFile(DataFile dataFile) {
    verifyIfAllowedToPerformEncryptionOnDataFile();
    EncryptedDataFile encryptedDataFile = bDocCrypto.encryptDataFile(dataFile);
    getDataFiles().remove(dataFile);
    getDataFiles().add(encryptedDataFile);
    return encryptedDataFile;
  }

  @Override
  public DataFile decryptDataFile(DataFile encryptedDataFile) {
    return bDocCrypto.decryptDataFile(encryptedDataFile);
  }

  @Override
  public BDocCryptoRecipient addRecipient(X509Certificate x509) {
    return bDocCrypto.addRecipient(x509);
  }

  @Override
  public List<BDocCryptoRecipient> getRecipients() {
    return bDocCrypto.getRecipients();
  }

  @Override
  public List<EncryptedDataFile> getEncryptedDataFiles() {
    return bDocCrypto.getEncryptedDataFiles();
  }

  @Override
  public void removeDataFile(DataFile file) {
    logger.info("Removing data file: " + file.getName());
    validateDataFilesRemoval();
    boolean wasRemovalSuccessful = dataFiles.remove(file);

    if (!wasRemovalSuccessful) {
      throw new DataFileNotFoundException(file.getName());
    }
  }

  @Override
  public void addSignature(Signature signature) {
    signatures.add(signature);
  }

  @Override
  public List<Signature> getSignatures() {
    return signatures;
  }

  @Override
  public void removeSignature(final Signature signature) {
    signatures.remove(signature);
  }

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public ValidationResult validate() {
    if (validationResult == null) {
      validationResult = validateContainer();
    }
    return validationResult;
  }

  protected ValidationResult validateContainer() {
    return new BDocContainerValidator(getConfiguration()).validate(getSignatures());
  }

  protected void validateIncomingSignature(Signature signature) {
    if (!(signature instanceof BDocSignature)) {
      throw new TechnicalException("BDoc signature must be an instance of BDocSignature");
    }
  }

  @Override
  public File saveAsFile(String filePath) {
    logger.debug("Saving container to file: " + filePath);
    File file = new File(filePath);
    AsicContainerCreator zipCreator = new AsicContainerCreator(file);
    writeAsicContainer(zipCreator);
    logger.info("Container was saved to file " + filePath);
    return file;
  }

  @Override
  public InputStream saveAsStream() {
    logger.debug("Saving container as stream");
    AsicContainerCreator zipCreator = new AsicContainerCreator();
    writeAsicContainer(zipCreator);
    InputStream inputStream = zipCreator.fetchInputStreamOfFinalizedContainer();
    logger.info("Container was saved to stream");
    return inputStream;
  }

  public Configuration getConfiguration() {
    return configuration;
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    signatures = extendAllSignaturesProfile(profile, signatures, dataFiles);
  }

  protected List<Signature> extendAllSignaturesProfile(SignatureProfile profile, List<Signature> signatures, List<DataFile> dataFiles) {
    logger.info("Extending all signatures' profile to " + profile.name());
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    DSSDocument firstDetachedContent = detachedContentCreator.getFirstDetachedContent();
    List<DSSDocument> detachedContentList = detachedContentCreator.getDetachedContentList();
    SignatureExtender signatureExtender = new SignatureExtender(getConfiguration(), firstDetachedContent);
    List<DSSDocument> extendedSignatureDocuments = signatureExtender.extend(signatures, profile);
    List<Signature> extendedSignatures = parseSignatureFiles(extendedSignatureDocuments, detachedContentList);
    logger.debug("Finished extending all signatures");
    return extendedSignatures;
  }

  protected List<Signature> parseSignatureFiles(List<DSSDocument> signatureFiles, List<DSSDocument> detachedContents) {
    Configuration configuration = getConfiguration();
    BDocSignatureOpener signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
    List<Signature> signatures = new ArrayList<>(signatureFiles.size());
    for (DSSDocument signatureFile : signatureFiles) {
      List<BDocSignature> bDocSignatures = signatureOpener.parse(signatureFile);
      signatures.addAll(bDocSignatures);
    }
    return signatures;
  }

  protected String createUserAgent() {
    if(!getSignatures().isEmpty()) {
      SignatureProfile profile = getSignatures().get(0).getProfile();
      return Helper.createBDocUserAgent(profile);
    }
    return Helper.createBDocUserAgent();
  }

  protected void validateDataFilesRemoval() {
    if (!getSignatures().isEmpty()) {
      logger.error("Datafiles cannot be removed from an already signed container");
      throw new RemovingDataFileException();
    }
  }

  protected void verifyIfAllowedToAddDataFile(String fileName) {
    if (getSignatures().size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    checkForDuplicateDataFile(fileName);
  }

  protected void verifyIfAllowedToPerformEncryptionOnDataFile() {
    if (!getSignatures().isEmpty()) {
      String errorMessage = "Datafiles cannot be encrypted or decrypted in containers where signatures are already present";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
  }

  private void checkForDuplicateDataFile(String fileName) {
    logger.debug("");
    for (DataFile dataFile : getDataFiles()) {
      String dataFileName = dataFile.getName();
      if (StringUtils.equals(dataFileName, fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        logger.error(errorMessage);
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  //#region -- Deprecated functions --
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
  @Deprecated
  public void addRawSignature(byte[] signatureDocument) {
    logger.info("Adding raw signature");
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
      logger.error("Failed to read signature stream: " + e.getMessage());
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
    return null;
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
  public void removeDataFile(String fileName) {
    logger.info("Removing data file: " + fileName);
    validateDataFilesRemoval();

    for (DataFile dataFile : dataFiles) {
      String name = dataFile.getName();
      if (StringUtils.equals(fileName, name)) {
        dataFiles.remove(dataFile);
        logger.debug("Data file has been removed");
        return;
      }
    }

    throw new DataFileNotFoundException(fileName);
  }

  @Override
  @Deprecated
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotSupportedException("Prepare signing method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public String getSignatureProfile() {
    throw new NotSupportedException("Getting signature profile method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotSupportedException("Setting signature parameters method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    signatures.remove(signatureId);
  }

  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    throw new NotSupportedException("Getting digest algorithm method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    throw new NotSupportedException("Sign method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    throw new NotSupportedException("Sign raw method is not supported by BDoc container");
  }

  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Setting signature profile method is not supported by BDoc container");
  }
  //#endregion -- Deprecated functions --

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = createUserAgent();
    zipCreator.setZipComment(userAgent);
    zipCreator.writeAsiceMimeType();

    writeAsicContainerContent(zipCreator);

    zipCreator.finalizeZipFile();
  }

  protected void writeAsicContainerContent(AsicContainerCreator zipCreator) {
    int startingSignatureFileIndex = 0;

    zipCreator.writeManifest(getDataFiles());
    zipCreator.writeDataFiles(getPlainDataFiles());
    zipCreator.writeSignatures(getSignatures(), startingSignatureFileIndex);
    bDocCrypto.writeToAsicContainer(zipCreator);
  }
}
