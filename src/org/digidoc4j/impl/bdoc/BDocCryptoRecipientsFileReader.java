package org.digidoc4j.impl.bdoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DigiDoc4JXMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import sun.security.x509.X509CertImpl;

/**
 * Created by Kaarel Raspel on 27/03/17.
 */
public class BDocCryptoRecipientsFileReader {

  private static Validator validator;

  static {
    DSSXMLUtils.registerNamespace("denc", "http://www.w3.org/2001/04/xmlenc#");
    DSSXMLUtils.registerNamespace("xhtml", "http://www.w3.org/1999/xhtml");
  }

  public BDocCryptoRecipientsFile read(InputStream inputStream) {
    Document document = DSSXMLUtils.buildDOM(inputStream);
    return read(document);
  }

  public BDocCryptoRecipientsFile read(File file) {
    try {
      return read(new FileInputStream(file));
    } catch (FileNotFoundException ex) {
      throw new DigiDoc4JException("File \"" + file.getName() + "\" not found", ex);
    }
  }

  private BDocCryptoRecipientsFile read(Document document) {
    validate(document);

    Element rootElement = document.getDocumentElement();
    Element keyInfo = DSSXMLUtils.getElement(rootElement, "./ds:KeyInfo");

    String fileEncMethodURI = getEncryptionMethodAlgorithmURI(rootElement);
    List<BDocCryptoRecipient> bDocCryptoRecipients = getBDocCryptoRecipients(keyInfo);
    List<String> encrypedFileNames = getBDocCryptoEncrypedFilenames(rootElement);

    return new BDocCryptoRecipientsFile(
        fileEncMethodURI,
        bDocCryptoRecipients,
        encrypedFileNames
    );
  }

  private List<String> getBDocCryptoEncrypedFilenames(Element rootElement) {
    List<String> fileNames = new ArrayList<>();

    NodeList fileNameElements = DSSXMLUtils.getNodeList(
        rootElement,
        "./denc:EncryptionProperties/denc:EncryptionProperty[@Id=\"Filenames\"]/xhtml:filename"
    );
    for (int index = 0; index < fileNameElements.getLength(); index++) {
      Node fileNameElement = fileNameElements.item(index);
      String fileName = fileNameElement.getTextContent();
      fileNames.add(fileName);
    }

    return fileNames;
  }

  private String getEncryptionMethodAlgorithmURI(Element element) {
    return DSSXMLUtils.getValue(element, "./denc:EncryptionMethod/@Algorithm");
  }

  List<BDocCryptoRecipient> getBDocCryptoRecipients(Element keyInfo) {
    List<BDocCryptoRecipient> bDocCryptoRecipients = new ArrayList<>();

    NodeList encryptedKeys = DSSXMLUtils.getNodeList(keyInfo, "./denc:EncryptedKey");
    for (int index = 0; index < encryptedKeys.getLength(); index++) {
      Element encryptedKey = (Element) encryptedKeys.item(index);

      String encryptionMethodURI = getEncryptionMethodAlgorithmURI(encryptedKey);
      X509Cert cert = getX509Cert(encryptedKey);
      byte[] cryptogram = getCryptogram(encryptedKey);

      bDocCryptoRecipients.add(new BDocCryptoRecipient(
          encryptionMethodURI,
          cert,
          cryptogram,
          true
      ));
    }

    return bDocCryptoRecipients;
  }

  private X509Cert getX509Cert(Element encryptedKey) {
    String x509Base64 = DSSXMLUtils.getValue(encryptedKey, "./ds:KeyInfo/ds:X509Data/ds:X509Certificate");
    byte[] x509Bytes = Base64.decodeBase64(x509Base64);
    try {
      return new X509Cert(new X509CertImpl(x509Bytes));
    } catch (CertificateException ex) {
      throw new DigiDoc4JXMLException("Invalid certificate found", ex);
    }
  }

  private byte[] getCryptogram(Element encryptedKey) {
    String cryptogramBase64 = DSSXMLUtils.getValue(encryptedKey, "./denc:CipherData/denc:CipherValue/text()");
    return Base64.decodeBase64(cryptogramBase64);
  }

  private void validate(Document document) {
    initValidatorIfNeeded();

    DOMSource domSource = new DOMSource(document);
    try {
      validator.validate(domSource);
    } catch (SAXException ex) {
      throw new DigiDoc4JXMLException("Invalid XML-ENC document", ex);
    } catch (IOException ex) {
      throw new DigiDoc4JXMLException(ex);
    }
  }

  private void initValidatorIfNeeded() {
    if (validator != null) return;

    try {
      Schema schema = WSSUtils.loadXMLSecuritySchemas();
      this.validator = schema.newValidator();
    } catch (SAXException ex) {
      throw new DigiDoc4JXMLException("Could not initialize XML validator", ex);
    }
  }
}
