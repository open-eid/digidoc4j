package org.digidoc4j.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Utility to generate keystore.
 */
public final class KeystoreGenerator {

  private static final String DEFAULT_KEYSTORE_CERTIFICATES_FILEPATH = "keystore/keystore_certs";
  private static final String DEFAULT_KEYSTORE_FILEPATH = "keystore/keystore.jks";
  private static final String DEFAULT_KEYSTORE_PASSWORD = "digidoc4j-password";
  private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

  private static final String TEST_KEYSTORE_CERTIFICATES_FILEPATH = "keystore/test_keystore_certs/";
  private static final String TEST_KEYSTORE_FILEPATH = "keystore/test-keystore.jks";

  private String keyStoreCertificateFilepath;
  private String keyStoreFilepath;
  private String keyStorePassword;

  /**
   * @param args input arguments
   */
  public static void main(String[] args) {
    try {
      KeystoreGenerator.aGenerator()
          .withCertificateDirectory(TEST_KEYSTORE_CERTIFICATES_FILEPATH)
          .withKeyStoreFilepath(TEST_KEYSTORE_FILEPATH)
          .generateKeystore();
    } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
      e.printStackTrace();
    }
  }

  private KeystoreGenerator() {}

  public static KeystoreGenerator aGenerator() {
    return new KeystoreGenerator();
  }

  public KeystoreGenerator withCertificateDirectory(String keyStoreCertificateFilepath) {
    this.keyStoreCertificateFilepath = keyStoreCertificateFilepath;
    return this;
  }

  public KeystoreGenerator withKeyStoreFilepath(String keyStoreFilepath) {
    this.keyStoreFilepath = keyStoreFilepath;
    return this;
  }

  public KeystoreGenerator withKeyStorePassword(String keyStorePassword) {
    this.keyStorePassword = keyStorePassword;
    return this;
  }

  /**
   * Generate a keystore with default mandatoryOptions.
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  public void generateKeystore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    keyStoreFilepath = keyStoreFilepath == null ? DEFAULT_KEYSTORE_FILEPATH : keyStoreFilepath;
    keyStoreCertificateFilepath = keyStoreCertificateFilepath == null ? DEFAULT_KEYSTORE_CERTIFICATES_FILEPATH : keyStoreCertificateFilepath;
    keyStorePassword = keyStorePassword == null ? DEFAULT_KEYSTORE_PASSWORD : keyStorePassword;
    generateKeystore(keyStoreCertificateFilepath, keyStoreFilepath, keyStorePassword);
  }

  /**
   * Generates a java.security.KeyStore on the specified path, filled with certificates from the specified path and
   * protected with the specified password.
   * @param keyStoreCertsFilepath Path to directory that holds necessary certificates.
   * @param keyStoreFilepath Path where to create the Keystore.
   * @param keyStorePassword Keystore Password.
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   */
  private void generateKeystore(String keyStoreCertsFilepath, String keyStoreFilepath, String keyStorePassword)
      throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    createKeystore(keyStoreFilepath, keyStorePassword);
    KeyStore store = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
    loadIntoKeystoreFormFile(store, keyStoreFilepath, keyStorePassword);

    File dir = new File(keyStoreCertsFilepath);
    File[] directoryListing = dir.listFiles();
    if (directoryListing != null) {
      for (File child : directoryListing) {
        addCertificate(store, child.getPath());
      }
      saveKeystoreToFile(store, keyStoreFilepath, keyStorePassword);
      readKeyStore(keyStoreFilepath, keyStorePassword);
    } else {
      System.out.println("No certificates found!");
    }
  }

  private void addCertificate(KeyStore store, String filepath) throws KeyStoreException, IOException {
    try (InputStream fis = new FileInputStream(filepath)) {
      CertificateToken europanCert = DSSUtils.loadCertificate(fis);
      System.out.println("Adding certificate " + filepath);
      displayCertificateDigests(europanCert);

      store.setCertificateEntry(UUID.randomUUID().toString(), europanCert.getCertificate());
    }
  }

  private void displayCertificateDigests(CertificateToken europanCert) {
    byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, europanCert.getEncoded());
    byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, europanCert.getEncoded());
    System.out.println("SHA256 digest (Hex) : " + getPrintableHex(digestSHA256));
    System.out.println("SHA1 digest (Hex) : " + getPrintableHex(digestSHA1));
    System.out.println("SHA256 digest (Base64) : " + Base64.encodeBase64String(digestSHA256));
    System.out.println("SHA1 digest (Base64) : " + Base64.encodeBase64String(digestSHA1));
  }

  private String getPrintableHex(byte[] digest) {
    String hexString = Hex.encodeHexString(digest);
    // Add space every two characters
    return hexString.replaceAll("", "$0 ");
  }

  private void readKeyStore(String keyStoreFilepath, String keyStorePassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    KeyStore store = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
    loadIntoKeystoreFormFile(store, keyStoreFilepath, keyStorePassword);

    Enumeration<String> aliases = store.aliases();
    while (aliases.hasMoreElements()) {
      final String alias = aliases.nextElement();
      if (store.isCertificateEntry(alias)) {
        Certificate certificate = store.getCertificate(alias);
        CertificateToken certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
        System.out.println(certificateToken);
      }
    }
  }

  private void createKeystore(String keyStoreFilepath, String keyStorePassword) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    KeyStore trustStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
    trustStore.load(null, keyStorePassword.toCharArray());
    Path pathToKeystore = Paths.get(keyStoreFilepath);
    pathToKeystore.getParent().toFile().mkdirs();
    saveKeystoreToFile(trustStore, keyStoreFilepath, keyStorePassword);
  }

  private static void loadIntoKeystoreFormFile(KeyStore store, String keyStoreFilepath, String keyStorePassword) throws IOException, CertificateException, NoSuchAlgorithmException {
    try (InputStream inputStream = new FileInputStream(keyStoreFilepath)) {
      store.load(inputStream, keyStorePassword.toCharArray());
    }
  }

  private static void saveKeystoreToFile(KeyStore store, String keyStoreFilepath, String keyStorePassword) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    try (OutputStream outputStream = new FileOutputStream(keyStoreFilepath)) {
      store.store(outputStream, keyStorePassword.toCharArray());
    }
  }
}
