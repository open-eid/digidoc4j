package org.digidoc4j.impl.bdoc;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

/**
 * Created by Kaarel Raspel on 24/03/17.
 */
public class BDocCryptoRecipientsFile implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(BDocCryptoRecipientsFile.class);
  public static final String XML_PATH = "META-INF/recipients.xml";
  private List<BDocCryptoRecipient> bDocCryptoRecipients = new ArrayList<>();
  private List<String> encrypedFileNames = new ArrayList<>();

  private String fileEncMethodURI;

  public BDocCryptoRecipientsFile(String fileEncMethodURI) {
    this(fileEncMethodURI, Lists.<BDocCryptoRecipient>newArrayList());
  }

  public BDocCryptoRecipientsFile(String fileEncMethodURI, List<BDocCryptoRecipient> bDocCryptoRecipients) {
    this(fileEncMethodURI, bDocCryptoRecipients, Lists.<String>newArrayList());
  }

  public BDocCryptoRecipientsFile(String fileEncMethodURI, List<BDocCryptoRecipient> bDocCryptoRecipients, List<String> encrypedFileNames) {
    setFileEncMethodURI(fileEncMethodURI);
    this.bDocCryptoRecipients = bDocCryptoRecipients;
    this.encrypedFileNames = encrypedFileNames;
  }

  public BDocCryptoRecipient addRecipient(X509Certificate x509Certificate, SecretKey dataEncryptionKey) {
    String algorithmW3cURI = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15; // TODO: Get from parameter
    BDocCryptoRecipient bDocCryptoRecipient = new BDocCryptoRecipient(algorithmW3cURI, x509Certificate, dataEncryptionKey);
    bDocCryptoRecipients.add(bDocCryptoRecipient); // TODO: Verify not present already
    return bDocCryptoRecipient;
  }

  public List<BDocCryptoRecipient> getBDocCryptoRecipients() {
    return bDocCryptoRecipients;
  }

  public String getDataFileEncryptionAlgorithmURI() {
    return fileEncMethodURI;
  }

  public List<String> getEncrypedFileNames() {
    return encrypedFileNames;
  }

  public void setFileEncMethodURI(String fileEncMethodURI) {
    Helper.ensureNotAlgorithmURI(fileEncMethodURI);
    this.fileEncMethodURI = fileEncMethodURI;
  }

  public String getFileEncMethodURI() {
    return fileEncMethodURI;
  }
}
