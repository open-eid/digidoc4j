package org.digidoc4j.impl.bdoc;

import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.FilesContainer;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JCryptoException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.asic.AsicContainerCreator;
import org.digidoc4j.CryptoContainer;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

/**
 * Created by Kaarel Raspel on 22/03/17.
 */
public class BDocCrypto implements CryptoContainer, Serializable {

  private static final Logger logger = LoggerFactory.getLogger(BDocCrypto.class);
  private FilesContainer filesContainer;

  private BDocCryptoRecipientsFile bDocCryptoRecipientsFile;
  private transient Cipher dataCipher;
  private transient SecretKey dataEncryptionKey;
  private transient final SecureRandom secureRandom = new SecureRandom();

  public BDocCrypto(FilesContainer filesContainer) {
    this(filesContainer, Configuration.getInstance());
  }

  public BDocCrypto(FilesContainer filesContainer, Configuration configuration) {
    this(filesContainer, new BDocCryptoRecipientsFile(configuration.getCDocEncyptionAlgorithmW3cURI()));
  }

  public BDocCrypto(FilesContainer filesContainer, BDocCryptoRecipientsFile bDocCryptoRecipientsFile) {
    this.filesContainer = filesContainer;
    this.bDocCryptoRecipientsFile = bDocCryptoRecipientsFile;
  }

  @Override
  public ValidationResult validate() {
    return null;
  }

  @Override
  public void setEncryptionKey(SecretKey key) {
    String algorithmW3cURI = this.bDocCryptoRecipientsFile.getDataFileEncryptionAlgorithmURI();
    String algorithm = Helper.ensureNotAlgorithmURI(algorithmW3cURI);
    if (!StringUtils.containsIgnoreCase(algorithm, key.getAlgorithm())) {
      throw new DigiDoc4JCryptoException(MessageFormat.format(
          "Invalid key algorithm. Required: {0}, Provided: {1}",
          algorithm, key.getAlgorithm()
      ));
    }
    this.dataEncryptionKey = key;
  }

  @Override
  public void setEncryptionKey(byte[] keyBytes) {
    String algorithmW3cURI = this.bDocCryptoRecipientsFile.getDataFileEncryptionAlgorithmURI();
    String algorithm = Helper.ensureNotAlgorithmURI(algorithmW3cURI).split("/")[0];
    SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
    this.dataEncryptionKey = secretKey;
  }

  @Override
  public void generateEncryptionKey() {
    generateEncryptionKey(this.bDocCryptoRecipientsFile.getFileEncMethodURI());
  }

  @Override
  public void generateEncryptionKey(String algorithmW3cURI) {
    try {
      int keyLength = Helper.getKeySizeFor(algorithmW3cURI);
      String keyAlgorithm = Helper.ensureNotAlgorithmURI(algorithmW3cURI).split("/")[0];
      KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
      keyGenerator.init(keyLength, secureRandom);
      this.dataEncryptionKey = keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException ex) {
      throw new DigiDoc4JCryptoException(ex.getMessage(), ex);
    }
  }

  @Override
  public List<EncryptedDataFile> getEncryptedDataFiles() {
    List<EncryptedDataFile> encryptedDataFiles = Lists.newArrayList();;
    List<DataFile> dataFiles = filesContainer.getDataFiles();
    if (dataFiles.isEmpty()) {
      return encryptedDataFiles;
    }

    for (DataFile dataFile : dataFiles) {
      if (dataFile instanceof EncryptedDataFile) {
        encryptedDataFiles.add((EncryptedDataFile) dataFile);
      }
    }

    return encryptedDataFiles;
  }

  @Override
  public List<DataFile> getPlainDataFiles() {
    List<DataFile> plainDataFiles = Lists.newArrayList();;
    List<DataFile> dataFiles = filesContainer.getDataFiles();
    if (dataFiles.isEmpty()) {
      return plainDataFiles;
    }

    for (DataFile dataFile : dataFiles) {
      if (!(dataFile instanceof EncryptedDataFile)) {
        plainDataFiles.add(dataFile);
      }
    }

    return plainDataFiles;
  }

  @Override
  public EncryptedDataFile encryptDataFile(DataFile dataFile) {
    return (EncryptedDataFile) performCryptoOperation(dataFile, Cipher.ENCRYPT_MODE);
  }

  @Override
  public DataFile decryptDataFile(DataFile encryptedDataFile) {
    return performCryptoOperation(encryptedDataFile, Cipher.DECRYPT_MODE);
  }

  @Override
  public BDocCryptoRecipient addRecipient(X509Certificate x509) {
    verifyDataEncryptionKeyPresence();
    return bDocCryptoRecipientsFile.addRecipient(x509, dataEncryptionKey);
  }

  @Override
  public List<BDocCryptoRecipient> getRecipients() {
    return bDocCryptoRecipientsFile.getBDocCryptoRecipients();
  }

  public Cipher getDataCipher() {
    ensureDataCipher(bDocCryptoRecipientsFile.getDataFileEncryptionAlgorithmURI());
    return dataCipher;
  }

  private DataFile performCryptoOperation(DataFile dataFile, int encOrDec) {
    verifyDataEncryptionKeyPresence();
    checkEncryptionFileClash(dataFile, encOrDec == Cipher.DECRYPT_MODE);

    Cipher cipher = initCipher(encOrDec, getDataCipher(), this.dataEncryptionKey);
    try (CipherInputStream cipherInputStream = new CipherInputStream(dataFile.getStream(), cipher)) {
      return encOrDec == Cipher.ENCRYPT_MODE
          ? new EncryptedDataFile(cipherInputStream, convertName(dataFile, encOrDec), dataFile.getMediaType())
          : new DataFile(cipherInputStream, convertName(dataFile, encOrDec), dataFile.getMediaType());
    } catch (IOException ex) {
      throw new DigiDoc4JCryptoException("Could not perform DataFile crypto operation", ex);
    }
  }

  private Cipher initCipher(int encOrDec, Cipher cipher, Key key) {
    try {
      cipher.init(encOrDec, key, new IvParameterSpec(new byte[16]));
      return cipher;
    } catch (GeneralSecurityException ex) {
      throw new DigiDoc4JCryptoException("Could not initialize cipher", ex);
    }
  }

  private static String convertName(DataFile dataFile, int encOrDec) {
    String fileName = dataFile.getDocument().getName();
    if (encOrDec == Cipher.ENCRYPT_MODE) {
      return fileName + ".enc";
    } else {
      return fileName.replaceAll("\\.enc$", "");
    }
  }

  private void ensureDataCipher(String algorithmW3cURI) {
    this.bDocCryptoRecipientsFile.setFileEncMethodURI(algorithmW3cURI);
    if (this.dataCipher == null) {
      this.dataCipher = Helper.getCipherFor(algorithmW3cURI);
    }
  }

  private void checkEncryptionFilesClash(List<DataFile> dataFiles) {
    Set<DataFile> plainDataFilesSet = ImmutableSet.copyOf(dataFiles);
    Set<EncryptedDataFile> encryptedDataFilesSet = ImmutableSet.copyOf(getEncryptedDataFiles());
    Sets.SetView<DataFile> alreadyEncryptedDataFiles = Sets.intersection(plainDataFilesSet, encryptedDataFilesSet);
    if (!alreadyEncryptedDataFiles.isEmpty()) {
      throw new DigiDoc4JException("");
    }
  }

  private void checkEncryptionFileClash(DataFile dataFile, boolean isEncrypted ) {
    if (!isEncrypted && isEncryptedDataFile(dataFile)) {
      throw new DigiDoc4JException("DataFile is already encrypted");
    }
    if (isEncrypted && !isEncryptedDataFile(dataFile)) {
      throw new DigiDoc4JException("DataFile is not encrypted");
    }
  }

  private void verifyDataEncryptionKeyPresence() {
    if (dataEncryptionKey == null) {
      throw new DigiDoc4JCryptoException("Data encryption key is missing. Generate or provide one.");
    }
  }

  public boolean isEncryptedDataFile(DataFile dataFile) {
    return Iterables.contains(getEncryptedDataFiles(), dataFile);
  }

  public void writeToAsicContainer(AsicContainerCreator zipCreator) {
    List<EncryptedDataFile> encryptedDataFiles = getEncryptedDataFiles();
    if (encryptedDataFiles.isEmpty()) return;

    zipCreator.writeEncryptedDataFiles(encryptedDataFiles);
    byte[] recipientsFileBytes = new BDocCryptoRecipientsFileWriter(bDocCryptoRecipientsFile).getBytes(encryptedDataFiles);
    zipCreator.writeCryptoRecipients(recipientsFileBytes);
  }
}
