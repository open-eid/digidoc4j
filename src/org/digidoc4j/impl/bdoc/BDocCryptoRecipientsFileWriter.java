package org.digidoc4j.impl.bdoc;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;

import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * Created by Kaarel Raspel on 27/03/17.
 */
public class BDocCryptoRecipientsFileWriter {

  private final BDocCryptoRecipientsFile bDocCryptoRecipientsFile;

  static {
    DSSXMLUtils.registerNamespace("denc", "http://www.w3.org/2001/04/xmlenc#");
    DSSXMLUtils.registerNamespace("xhtml", "http://www.w3.org/1999/xhtml");
  }

  public BDocCryptoRecipientsFileWriter(BDocCryptoRecipientsFile bDocCryptoRecipientsFile) {
    this.bDocCryptoRecipientsFile = bDocCryptoRecipientsFile;
  }

  public byte[] getBytes(List<EncryptedDataFile> encryptedDataFiles) {
    List<BDocCryptoRecipient> bDocCryptoRecipients = bDocCryptoRecipientsFile.getBDocCryptoRecipients();
    String fileEncryptionAlgorithmURI = bDocCryptoRecipientsFile.getDataFileEncryptionAlgorithmURI();

    Document document = DSSXMLUtils.buildDOM(getResourceFile("xml-enc/baseDocument.xml"));

    setDataFileEncryptionAlgorithm(document, fileEncryptionAlgorithmURI);
    setFilenames(document, encryptedDataFiles);
    setRecipients(document, bDocCryptoRecipients);

    return DSSXMLUtils.transformDomToByteArray(document);
  }

  private static void setDataFileEncryptionAlgorithm(Document document, String algorithmURI) {
    Element encryptionMethod = DSSXMLUtils.getElement(rootElement(document), "./denc:EncryptionMethod");
    encryptionMethod.setAttribute("Algorithm", algorithmURI);
  }

  private static void setFilenames(Document document, List<EncryptedDataFile> filenames) {
    Element fileNamesElement = DSSXMLUtils.getElement(
        rootElement(document),
        "./denc:EncryptionProperties/denc:EncryptionProperty[@Id=\"Filenames\"]"
    );
    Element elementTemplate = DSSXMLUtils.buildDOM(getResourceFile("xml-enc/filenameElement.xml")).getDocumentElement();
    elementTemplate.removeAttribute("xmlns:xhtml");
    for (EncryptedDataFile dataFile : filenames) {
      Element element = (Element) elementTemplate.cloneNode(true);

      String fileName = dataFile.getDocument().getName();
      element.setTextContent(fileName);

      document.adoptNode(element);
      fileNamesElement.appendChild(element);
    }
  }

  private static Element rootElement(Document document) {
    return document.getDocumentElement();
  }

  private static void setRecipients(Document document, List<BDocCryptoRecipient> bDocCryptoRecipients) {
    Element keyInfoElement = DSSXMLUtils.getElement(rootElement(document), "./ds:KeyInfo");
    Element encryptedKeyTemplate = DSSXMLUtils.buildDOM(getResourceFile("xml-enc/encryptedKeyElement.xml")).getDocumentElement();
    encryptedKeyTemplate.removeAttribute("xmlns:denc");
    encryptedKeyTemplate.removeAttribute("xmlns:ds");
    for (BDocCryptoRecipient recipient : bDocCryptoRecipients) {
      Element encryptedKey = (Element) encryptedKeyTemplate.cloneNode(true);

      Element encryptionMethod = DSSXMLUtils.getElement(encryptedKey, "./denc:EncryptionMethod");
      Element x509Certificate = DSSXMLUtils.getElement(encryptedKey, "./ds:KeyInfo/ds:X509Data/ds:X509Certificate");
      Element cipherValue = DSSXMLUtils.getElement(encryptedKey, "./denc:CipherData/denc:CipherValue");

      encryptedKey.setAttribute("Recipient", recipient.getCert().getSubjectName(X509Cert.SubjectName.CN));
      encryptionMethod.setAttribute("Algorithm", recipient.getKeyEncryptionAlgorithmURI());
      x509Certificate.setTextContent(certToBase64(recipient.getCert()));
      cipherValue.setTextContent(bytesToBase64(recipient.getCryptogram()));

      document.adoptNode(encryptedKey);
      keyInfoElement.appendChild(encryptedKey);
    }
  }

  private static String certToBase64(X509Cert cert) {
    try {
      byte[] certBytes = cert.getX509Certificate().getEncoded();
      return bytesToBase64(certBytes);
    } catch (CertificateEncodingException ex) {
      throw new DigiDoc4JException("Could not encode certificate", ex);
    }
  }

  private static String bytesToBase64(byte[] bytes) {
    return Base64.encodeBase64String(bytes);
  }

  private static String getResourceFile(String path) {
    URL fileUrl = Resources.getResource(path);
    try {
      return Resources.toString(fileUrl, Charsets.UTF_8);
    } catch (IOException ex) {
      throw new DigiDoc4JException(ex);
    }
  }
}
