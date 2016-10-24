/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.manifest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.xml.security.signature.Reference;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * For validating meta data within the manifest file and signature files.
 */
public class ManifestValidator {
  private static final Logger logger = LoggerFactory.getLogger(ManifestValidator.class);
  public static final String MANIFEST_PATH = "META-INF/manifest.xml";
  public static final String MIMETYPE_PATH = "mimetype";
  private List<DSSDocument> detachedContents;
  private ManifestParser manifestParser;
  private Collection<Signature> signatures;

  public ManifestValidator(ManifestParser manifestParser, List<DSSDocument> detachedContents, Collection<Signature> signatures) {
    this.manifestParser = manifestParser;
    this.detachedContents = detachedContents;
    this.signatures = signatures;
  }

  /**
   * Validate the container.
   *
   * @return list of error messages
   */
  public List<String> validateDocument() {
    logger.debug("");
    if (!manifestParser.containsManifestFile()) {
      String errorMessage = "Container does not contain manifest file.";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    List<String> errorMessages = new ArrayList<>();
    Map<String, ManifestEntry> manifestEntries = manifestParser.getManifestFileItems();
    Set<ManifestEntry> signatureEntries = new HashSet<>();

    for (Signature signature : signatures) {
      signatureEntries = getSignatureEntries((BDocSignature) signature);

      errorMessages.addAll(validateEntries(manifestEntries, signatureEntries, signature.getId()));
    }

    errorMessages.addAll(validateFilesInContainer(signatureEntries));

    logger.info("Validation of meta data within the manifest file and signature files error count: " + errorMessages.size());
    return errorMessages;
  }

  private List<String> validateFilesInContainer(Set<ManifestEntry> signatureEntries) {
    logger.debug("");
    ArrayList<String> errorMessages = new ArrayList<>();

    if (signatureEntries.size() == 0)
      return errorMessages;

    Set<String> signatureEntriesFileNames = getFileNamesFromManifestEntrySet(signatureEntries);
    List<String> filesInContainer = getFilesInContainer();
    for(String fileInContainer: filesInContainer) {
      if(!signatureEntriesFileNames.contains(fileInContainer)) {
        logger.error("Container contains unsigned data file '" + fileInContainer + "'");
        errorMessages.add("Container contains a file named " + fileInContainer + " which is not found in the signature file");
      }
    }
    return errorMessages;
  }

  private Set<String> getFileNamesFromManifestEntrySet(Set<ManifestEntry> signatureEntries) {
    Set<String> signatureEntriesFileNames = new HashSet<>(signatureEntries.size());


    for (ManifestEntry entry : signatureEntries) {
      signatureEntriesFileNames.add(entry.getFileName());
    }
    return signatureEntriesFileNames;
  }

  @SuppressWarnings("unchecked")
  static List<String> validateEntries(Map<String, ManifestEntry> manifestEntries, Set<ManifestEntry> signatureEntries,
                                      String signatureId) {
    logger.debug("");
    ArrayList<String> errorMessages = new ArrayList<>();

    if (signatureEntries.size() == 0)
      return errorMessages;

    Set<ManifestEntry> one = new HashSet(manifestEntries.values());
    Set<ManifestEntry> two = new HashSet(signatureEntries);
    one.removeAll(signatureEntries);
    two.removeAll(manifestEntries.values());

    for (ManifestEntry manifestEntry : one) {

      String fileName = manifestEntry.getFileName();
      ManifestEntry signatureEntry = signatureEntryForFile(fileName, signatureEntries);
      if (signatureEntry != null) {
        errorMessages.add("Manifest file has an entry for file " + fileName + " with mimetype " +
            manifestEntry.getMimeType() + " but the signature file for signature " + signatureId +
            " indicates the mimetype is " + signatureEntry.getMimeType());
        two.remove(signatureEntry);
      } else {
        errorMessages.add("Manifest file has an entry for file " + fileName + " with mimetype "
            + manifestEntry.getMimeType() + " but the signature file for signature " + signatureId +
            " does not have an entry for this file");
      }
    }

    for (ManifestEntry manifestEntry : two) {
      errorMessages.add("The signature file for signature " + signatureId + " has an entry for file "
          + manifestEntry.getFileName() + " with mimetype " + manifestEntry.getMimeType()
          + " but the manifest file does not have an entry for this file");
    }

    return errorMessages;
  }

  private static ManifestEntry signatureEntryForFile(String fileName, Set<ManifestEntry> signatureEntries) {
    logger.debug("File name: " + fileName);
    for (ManifestEntry signatureEntry : signatureEntries) {
      if (fileName.equals(signatureEntry.getFileName())) {
        return signatureEntry;
      }
    }
    return null;
  }

  private Set<ManifestEntry> getSignatureEntries(BDocSignature signature) {
    Set<ManifestEntry> signatureEntries = new HashSet<>();
    List<Reference> references = signature.getOrigin().getReferences();
    for (Reference reference : references) {
      if (reference.getType().equals("")) {
        String mimeTypeString = null;

        Node signatureNode = signature.getOrigin().getDssSignature().getSignatureElement();
        Node node = DSSXMLUtils.getNode(signatureNode, "./ds:SignedInfo/ds:Reference[@URI=\"" + reference.getURI() + "\"]");
        if (node != null) {
          String referenceId = node.getAttributes().getNamedItem("Id").getNodeValue();
          mimeTypeString = DSSXMLUtils.getValue(signatureNode,
              "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/" +
                  "xades:SignedDataObjectProperties/xades:DataObjectFormat" +
                  "[@ObjectReference=\"#" + referenceId + "\"]/xades:MimeType");
        }

        // TODO: mimeTypeString == null ? node == null?
         String uri = getFileURI(reference);
         signatureEntries.add(new ManifestEntry(uri, mimeTypeString));
      }
    }

    return signatureEntries;
  }

    private String getFileURI(Reference reference) {
        String uri = reference.getURI();
        try {
          uri = new URI(uri).getPath();
        } catch (URISyntaxException e) {
          logger.warn("Does not parse as an URI, therefore assuming it's not encoded: '" + uri + "'");
        }

        return uri;
    }

  private List<String> getFilesInContainer() {
    List<String> fileEntries = new ArrayList<>();

    List<String> signatureFileNames = getSignatureFileNames();

    for (DSSDocument detachedContent : detachedContents) {
      String name = detachedContent.getName();
      if (!(MANIFEST_PATH.equals(name) || ("META-INF/".equals(name)) || (MIMETYPE_PATH.equals(name)
          || signatureFileNames.contains(name)))) {
        fileEntries.add(name);
      }
    }
    return fileEntries;
  }

  private List<String> getSignatureFileNames() {
    List<String> signatureFileNames = new ArrayList<>();
    for (Signature signature :signatures) {
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
