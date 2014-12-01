/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.reference.ReferenceOctetStreamData;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * For validating meta data within the manifest file and signature files.
 */
public class ManifestValidator {
  static final Logger logger = LoggerFactory.getLogger(ManifestValidator.class);
  private InMemoryDocument manifestFile;
  private SignedDocumentValidator asicValidator;
  private List<DSSDocument> detachedContents;

  /**
   * Constructor.
   * @param validator Validator object
   */
  public ManifestValidator(SignedDocumentValidator validator) {
    asicValidator = validator;
    detachedContents = asicValidator.getDetachedContents();
    for (DSSDocument dssDocument : detachedContents) {
      if ("META-INF/manifest.xml".equals(dssDocument.getName())) {
        manifestFile = (InMemoryDocument) dssDocument;
        break;
      }
    }
  }

  /**
   * Validate the container.
   *
   * @param signatures list of signatures
   *
   * @return list of error messages
   */
  public List<String> validateDocument(List<Signature> signatures) {
    if (manifestFile == null)
      throw new DigiDoc4JException("Container does not contain manifest file.");

    List<String> errorMessages = new ArrayList<>();
    Set<ManifestEntry> manifestEntries = getManifestFileItems();
    Set<ManifestEntry> signatureEntries = new HashSet<>();

    for (Signature signature : signatures) {
      signatureEntries = getSignatureEntries((BDocSignature) signature);

      errorMessages.addAll(validateEntries(manifestEntries, signatureEntries, signature.getId()));
    }

    errorMessages.addAll(validateFilesInContainer(signatureEntries));

    return errorMessages;
  }

  private List<String> validateFilesInContainer(Set<ManifestEntry> signatureEntries) {
    ArrayList<String> errorMessages = new ArrayList<>();

    if (signatureEntries.size() == 0)
      return errorMessages;

    List<String> filesInContainer = new ArrayList<>(getFilesInContainer());

    if (filesInContainer.size() != signatureEntries.size()) {
      List<String> signatureEntriesFileNames = getFileNamesFromManifestEntrySet(signatureEntries);
      filesInContainer.removeAll(signatureEntriesFileNames);

      for (String fileName : filesInContainer) {
        errorMessages.add("Container contains a file named " + fileName + " which is not found in the signature "
            + "file");
      }
    }

    return errorMessages;
  }

  private List<String> getFileNamesFromManifestEntrySet(Set<ManifestEntry> signatureEntries) {
    List<String> signatureEntriesFileNames = new ArrayList<>();


    for (ManifestEntry entry : signatureEntries) {
      signatureEntriesFileNames.add(entry.getFileName());
    }
    return signatureEntriesFileNames;
  }

  @SuppressWarnings("unchecked")
  static List<String> validateEntries(Set<ManifestEntry> manifestEntries, Set<ManifestEntry> signatureEntries,
                                      String signatureId) {

    ArrayList<String> errorMessages = new ArrayList<>();

    if (signatureEntries.size() == 0)
      return errorMessages;

    Set<ManifestEntry> one = new HashSet(manifestEntries);
    Set<ManifestEntry> two = new HashSet(signatureEntries);
    one.removeAll(signatureEntries);
    two.removeAll(manifestEntries);


    for (ManifestEntry manifestEntry : one) {
      errorMessages.add("Manifest file has an entry for file " + manifestEntry.getFileName() + " with mimetype "
          + manifestEntry.getMimeType() + " but the signature file for signature " + signatureId + " does not.");
    }

    for (ManifestEntry manifestEntry : two) {
      errorMessages.add("The signature file for signature " + signatureId + " has an entry for file "
          + manifestEntry.getFileName() + " with mimetype " + manifestEntry.getMimeType()
          + " but the manifest file does not.");
    }

    return errorMessages;
  }

  private Set<ManifestEntry> getSignatureEntries(BDocSignature signature) {
    Set<ManifestEntry> signatureEntries = new HashSet<>();
    List<Reference> references = signature.getOrigin().getReferences();
    for (Reference reference : references) {
      if (reference.getType().equals("")) {
        ReferenceOctetStreamData referenceData = (ReferenceOctetStreamData) (reference.getReferenceData());
        signatureEntries.add(new ManifestEntry(referenceData.getURI(), referenceData.getMimeType()));
      }
    }
    return signatureEntries;
  }

  private Set<ManifestEntry> getManifestFileItems() {

    Set<ManifestEntry> entries = new HashSet<>();

    Element root = DSSXMLUtils.buildDOM(manifestFile).getDocumentElement();
    Node firstChild = root.getFirstChild();
    while (firstChild != null) {
      String nodeName = firstChild.getNodeName();
      if ("manifest:file-entry".equals(nodeName)) {
        NamedNodeMap attributes = firstChild.getAttributes();
        String textContent = attributes.getNamedItem("manifest:full-path").getTextContent();
        String mimeType = attributes.getNamedItem("manifest:media-type").getTextContent();
        if (!"/".equals(textContent))
          if (!entries.add(new ManifestEntry(textContent, mimeType))) {
            DigiDoc4JException digiDoc4JException = new DigiDoc4JException("duplicate entry in manifest file");
            logger.error(digiDoc4JException.getMessage());
            throw digiDoc4JException;
          }
      }
      firstChild = firstChild.getNextSibling();
    }

    return entries;
  }

  private List<String> getFilesInContainer() {
    List<String> fileEntries = new ArrayList<>();

    List<String> signatureFileNames = getSignatureFileNames();

    for (DSSDocument detachedContent : detachedContents) {
      String name = detachedContent.getName();
      if (!("META-INF/manifest.xml".equals(name) || ("META-INF/".equals(name)) || ("mimetype".equals(name)
          || signatureFileNames.contains(name)))) {
        fileEntries.add(name);
      }
    }
    return fileEntries;
  }

  private List<String> getSignatureFileNames() {
    List<String> signatureFileNames = new ArrayList<>();
    for (AdvancedSignature signature : asicValidator.getSignatures()) {
      String signatureFileName = "META-INF/signature" + signature.getId().toLowerCase() + ".xml";

      if (signatureFileNames.contains(signatureFileName)) {
        String errorMessage = "Duplicate signature file: " + signatureFileName;
        logger.error(errorMessage);
        throw new DigiDoc4JException(errorMessage);
      }

      signatureFileNames.add(signatureFileName);
    }
    return signatureFileNames;
  }
}
