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
import org.digidoc4j.SignatureBuilder;
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
import org.digidoc4j.impl.IndexedEntry;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

public class BDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(BDocContainer.class);
  private Configuration configuration;

  private List<DataFile> dataFiles = new ArrayList<>();
  private BDocContainerImpl bDocSigner = new BDocSigner(this);
  private BDocCrypto bDocCrypto = new BDocCrypto(this);

  private List<IndexedEntry<Signature>> signatureEntries = new ArrayList<>();

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
    bDocSigner.addSignature(signature);
  }

  @Override
  public List<Signature> getSignatures() {
    return Lists.transform(signatureEntries, new Function<IndexedEntry<Signature>, Signature>() {
      @Override
      public Signature apply(IndexedEntry<Signature> signatureEntry) {
        return signatureEntry.getEntry();
      }
    });
  }

  @Override
  public void removeSignature(final Signature signature) {
    Iterables.removeIf(signatureEntries, new Predicate<IndexedEntry>() {
      @Override
      public boolean apply(IndexedEntry signatureEntry) {
        return signatureEntry.equals(signature);
      }
    });
  }

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public ValidationResult validate() {
    return bDocSigner.validate();
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
    bDocSigner.extendSignatureProfile(profile, dataFiles);
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
    signatureEntries.remove(signatureId);
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
    zipCreator.writeDataFiles(getDataFiles());
    bDocSigner.writeAsicContainerSignatures(zipCreator, startingSignatureFileIndex);
    bDocSigner.writeAsicContainerCryptoData(zipCreator, startingSignatureFileIndex);
    zipCreator.writeSignatures(bDocSigner.getSignatures(), startingSignatureFileIndex);
  }
}
