package org.digidoc4j.impl.cdoc;

import java.io.File;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.CryptoFilesContainer;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.impl.bdoc.BDocCrypto;
import org.digidoc4j.impl.bdoc.BDocCryptoRecipient;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.MimeType;

/**
 * Created by Kaarel Raspel on 22/03/17.
 */
public class CDoc2Container implements CryptoFilesContainer {

  private static final Logger logger = LoggerFactory.getLogger(CDoc2Container.class);
  public final static MimeType MimeType = new MimeType("application/x-cryptodoc", "cdoc");
  private final Configuration configuration;
  protected BDocCrypto bDocCrypto = new BDocCrypto(this);
  private List<DataFile> dataFiles = new ArrayList<>();


  public CDoc2Container() {
    logger.debug("Instantiating CDoc2 container");
    configuration = Configuration.getInstance();
  }

  public CDoc2Container(Configuration configuration) {
    logger.debug("Instantiating BDoc container with configuration");
    this.configuration = configuration;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    DataFile dataFile = new DataFile(path, mimeType);
    addDataFile(dataFile);
    return dataFile;
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    DataFile dataFile = new DataFile(is, fileName, mimeType);
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
    checkForDuplicateDataFile(dataFile.getName());
    dataFiles.add(dataFile);
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

  public Configuration getConfiguration() {
    return configuration;
  }

  @Override
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  @Override
  public String getType() {
    return "CDOC2";
  }

  @Override
  public void removeDataFile(DataFile file) {
    if (!dataFiles.remove(file)) {
      logger.debug("Could not remove non-existing datafile from the container");
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

  @Override
  public ValidationResult validate() {
    return null;
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
  public List<EncryptedDataFile> getEncryptedDataFiles() {
    return bDocCrypto.getEncryptedDataFiles();
  }

  @Override
  public List<DataFile> getPlainDataFiles() {
    return bDocCrypto.getPlainDataFiles();
  }

  @Override
  public EncryptedDataFile encryptDataFile(DataFile dataFile) {
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

  protected void writeAsicContainer(AsicContainerCreator zipCreator) {
    String userAgent = Helper.createBDocUserAgent();
    zipCreator.setZipComment(userAgent);
    zipCreator.writeAsiceMimeType();

    zipCreator.writeManifest(getDataFiles());
    zipCreator.writeDataFiles(getPlainDataFiles());
    bDocCrypto.writeToAsicContainer(zipCreator);

    zipCreator.finalizeZipFile();
  }
}
