package org.digidoc4j;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;

import org.digidoc4j.impl.bdoc.BDocCryptoRecipient;

/**
 * Created by Kaarel Raspel on 23/03/17.
 */
public interface CryptoContainer extends BaseContainer {

  ValidationResult validate();

  void setEncryptionKey(SecretKey key);

  void setEncryptionKey(byte[] keyBytes);

  void generateEncryptionKey();

  void generateEncryptionKey(String algorithmW3cURI);

  List<EncryptedDataFile> getEncryptedDataFiles();

  List<DataFile> getPlainDataFiles();

  DataFile encryptDataFile(DataFile dataFile);

  DataFile decryptDataFile(DataFile encryptedDataFile);

  BDocCryptoRecipient addRecipient(X509Certificate x509);

  List<BDocCryptoRecipient> getRecipients();
}
