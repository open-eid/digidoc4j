package org.digidoc4j.impl.cdoc;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.Cipher;

import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.bdoc.BDocCryptoRecipient;
import org.junit.Test;

/**
 * Created by Kaarel Raspel on 30/03/17.
 */
public class CDoc2ContainerTest extends DigiDoc4JTestHelper {

  @Test
  public void bDoc_withCrypto_shouldWriteAndReadContainer() throws GeneralSecurityException {
    // Perpare
    ensureKeyPairAndX509();
    String data = "random text";
    DataFile memoryDataFile = new DataFile(data.getBytes(), "test.txt", "text/plain");

    // Test
    CDoc2Container cDoc2Container = new CDoc2Container();
    cDoc2Container.addDataFile(memoryDataFile);
    cDoc2Container.generateEncryptionKey();
    cDoc2Container.encryptDataFile(memoryDataFile);
    cDoc2Container.addRecipient(selfSignedCert);
    InputStream inputStream = cDoc2Container.saveAsStream();

    // Verify
    ExistingCDoc2Container existingCDocContainer = new ExistingCDoc2Container(inputStream);
    List<EncryptedDataFile> encryptedDataFiles = existingCDocContainer.getEncryptedDataFiles();
    assertEquals(1, encryptedDataFiles.size());
    List<BDocCryptoRecipient> recipients = existingCDocContainer.getRecipients();
    assertEquals(1, recipients.size());

    // Test
    BDocCryptoRecipient recipient = recipients.get(0);
    Cipher cipher = recipient.getCipher();
    cipher.init(Cipher.PRIVATE_KEY, keyPair.getPrivate());
    byte[] secretKeyBytes = cipher.doFinal(recipient.getCryptogram());
    existingCDocContainer.setEncryptionKey(secretKeyBytes);
    DataFile decryptedDataFile = existingCDocContainer.decryptDataFile(existingCDocContainer.getDataFiles().get(0));

    // Verify
    String decryptedData = new String(decryptedDataFile.getBytes());
    assertEquals(data, decryptedData);
  }
}
