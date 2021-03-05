/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.manifest;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.xml.security.signature.Reference;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * For validating meta data within the manifest file and signature files.
 */
public class ManifestValidator {
  public static final String MANIFEST_PATH = "META-INF/manifest.xml";
  public static final String MIMETYPE_PATH = "mimetype";
  private static final Logger logger = LoggerFactory.getLogger(ManifestValidator.class);
  private List<DSSDocument> detachedContents;
  private ManifestParser manifestParser;
  private Collection<Signature> signatures;

  public ManifestValidator(ManifestParser manifestParser, List<DSSDocument> detachedContents,
                           Collection<Signature> signatures) {
    this.manifestParser = manifestParser;
    this.detachedContents = detachedContents;
    this.signatures = signatures;
  }

  public static List<ManifestErrorMessage> validateEntries(Map<String, ManifestEntry> manifestEntries,
                                                           Set<ManifestEntry> signatureEntries,
                                                           String signatureId) {
    ArrayList<ManifestErrorMessage> errorMessages = new ArrayList<>();

    if (signatureEntries.size() == 0)
      return errorMessages;

    Set<ManifestEntry> one = new HashSet(manifestEntries.values());
    Set<ManifestEntry> onePrim = new HashSet(manifestEntries.values());
    Set<ManifestEntry> two = new HashSet(signatureEntries);
    Set<ManifestEntry> twoPrim = new HashSet();
    for (ManifestEntry manifestEntry : signatureEntries) {
      String mimeType = manifestEntry.getMimeType();
      String alterName = manifestEntry.getFileName().replaceAll("\\+", " ");
      twoPrim.add(new ManifestEntry(alterName, mimeType));
    }

    one.removeAll(signatureEntries);
    onePrim.removeAll(twoPrim);
    two.removeAll(manifestEntries.values());
    twoPrim.removeAll(manifestEntries.values());

    if (one.size() > 0 && onePrim.size() > 0) {
      for (ManifestEntry manifestEntry : one) {

        String fileName = manifestEntry.getFileName();
        ManifestEntry signatureEntry = signatureEntryForFile(fileName, signatureEntries);
        if (signatureEntry != null) {
          errorMessages.add(new ManifestErrorMessage("Manifest file has an entry for file <"
                  + fileName + "> with mimetype <"
                  + manifestEntry.getMimeType() + "> but the signature file for signature " + signatureId
                  + " indicates the mimetype is <" + signatureEntry.getMimeType() + ">", signatureId));
          two.remove(signatureEntry);
        } else {
          errorMessages.add(new ManifestErrorMessage("Manifest file has an entry for file <"
                  + fileName + "> with mimetype <"
                  + manifestEntry.getMimeType() + "> but the signature file for signature " + signatureId
                  + " does not have an entry for this file", signatureId));
        }
      }
    }

    if (two.size() > 0 && twoPrim.size() > 0) {
      for (ManifestEntry manifestEntry : two) {
        errorMessages.add(new ManifestErrorMessage("The signature file for signature "
                + signatureId + " has an entry for file <"
                + manifestEntry.getFileName() + "> with mimetype <" + manifestEntry.getMimeType()
                + "> but the manifest file does not have an entry for this file", signatureId));
      }
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

  /**
   * Validate the container.
   *
   * @return list of error messages
   */
  public List<ManifestErrorMessage> validateDocument() {
    if (!manifestParser.containsManifestFile()) {
      String errorMessage = "Container does not contain manifest file.";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    List<ManifestErrorMessage> errorMessages = new ArrayList<>();
    Map<String, ManifestEntry> manifestEntries = manifestParser.getManifestFileItems();
    Set<ManifestEntry> signatureEntries = new HashSet<>();

    for (Signature signature : signatures) {
      signatureEntries = getSignatureEntries(signature);

      errorMessages.addAll(validateEntries(manifestEntries, signatureEntries, signature.getId()));
    }

    errorMessages.addAll(validateFilesInContainer(signatureEntries));

    logger.info("Validation of meta data within the manifest file and signature files error count: "
            + errorMessages.size());
    return errorMessages;
  }

  private List<ManifestErrorMessage> validateFilesInContainer(Set<ManifestEntry> signatureEntries) {
    List<ManifestErrorMessage> errorMessages = new ArrayList<>();
    if (signatureEntries.size() == 0) {
      return errorMessages;
    }
    Set<String> signatureEntriesFileNames = this.getFileNamesFromManifestEntrySet(signatureEntries);
    List<String> filesInContainer = getFilesInContainer();
    for (String fileInContainer : filesInContainer) {
      String alterName = fileInContainer.replaceAll("\\ ", "+");
      if (!signatureEntriesFileNames.contains(fileInContainer) && !signatureEntriesFileNames.contains(alterName)) {
        errorMessages.add(new ManifestErrorMessage(String.format("Container contains a file named <%s> which is not "
                + "found in the signature file", fileInContainer)));
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

  private Set<ManifestEntry> getSignatureEntries(Signature signature) {
    Set<ManifestEntry> signatureEntries = new HashSet<>();
    XadesSignature origin;
    if (signature.getClass() == BDocSignature.class) {
      origin = ((BDocSignature) signature).getOrigin();
    } else {
      origin = ((AsicESignature) signature).getOrigin();
    }
    List<Reference> references = origin.getReferences();
    for (Reference reference : references) {
      if (reference.getType().equals("")) {
        String mimeTypeString = null;

        Node signatureNode = origin.getDssSignature().getSignatureElement();
        Node node = DomUtils.getNode(signatureNode, "./ds:SignedInfo/ds:Reference[@URI=\""
                + reference.getURI() + "\"]");
        if (node != null) {
          String referenceId = node.getAttributes().getNamedItem("Id").getNodeValue();
          String xAdESPrefix = origin.getDssSignature().getXAdESPaths().getNamespace().getPrefix();
          mimeTypeString = DomUtils.getValue(signatureNode,
                  "./ds:Object/" + xAdESPrefix + ":QualifyingProperties/" + xAdESPrefix + ":SignedProperties/"
                          + xAdESPrefix + ":SignedDataObjectProperties/" + xAdESPrefix + ":DataObjectFormat"
                          + "[@ObjectReference=\"#" + referenceId + "\"]/" + xAdESPrefix + ":MimeType");
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
    for (DSSDocument detachedContent : detachedContents) {
      String name = detachedContent.getName();
      fileEntries.add(name);
    }
    return fileEntries;
  }

}
