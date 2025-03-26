/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.asic.manifest.definition.ASiCManifestAttribute;
import eu.europa.esig.asic.manifest.definition.ASiCManifestPath;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * An entity for handling instances of {@code ASiCArchiveManifest}.
 */
public class AsicArchiveManifest implements Serializable {

  private static final Logger log = LoggerFactory.getLogger(AsicArchiveManifest.class);

  static {
    // Using DomUtils to parse the elements of ASiCArchiveManifest fails if appropriate namespaces are not registered.
    // As a workaround, make this dummy usage of ASiCManifestParser statically register all required namespaces for us.
    ASiCManifestParser.getLinkedManifest(Collections.emptyList(), StringUtils.EMPTY);
  }

  private final DSSDocument manifestDocument;

  private transient Reference referencedTimestamp;
  private transient List<DataReference> referencedDataObjects;
  private transient Set<String> uniqueNonNullEntryNames;

  /**
   * Creates an instance of AsicArchiveManifest by wrapping the specified DSSDocument.
   * NB: the constructor does not parse the manifest! The manifest is parsed lazily as needed.
   *
   * @param manifestDocument DSSDocument of an ASiCArchiveManifest
   */
  public AsicArchiveManifest(DSSDocument manifestDocument) {
    this.manifestDocument = Objects.requireNonNull(manifestDocument);
  }

  /**
   * Returns the DSSDocument of the manifest.
   *
   * @return DSSDocument of the manifest
   */
  public DSSDocument getManifestDocument() {
    return manifestDocument;
  }

  /**
   * Returns the timestamp token referenced by this manifest file.
   * Calling this method triggers the parsing process of the manifest if it has not been parsed already.
   *
   * @return referenced timestamp token
   */
  public Reference getReferencedTimestamp() {
    if (referencedTimestamp == null) {
      parseManifestContent();
    }

    return referencedTimestamp;
  }

  /**
   * Returns the list of data objects referenced by this manifest file.
   * Calling this method triggers the parsing process of the manifest if it has not been parsed already.
   *
   * @return list of referenced data objects
   */
  public List<DataReference> getReferencedDataObjects() {
    if (referencedDataObjects == null) {
      parseManifestContent();
    }

    return referencedDataObjects;
  }

  /**
   * Returns the set of non-null names of this manifest's entries.
   * Calling this method triggers the parsing process of the manifest if it has not been parsed already.
   *
   * @return set of non-null manifest entry names
   */
  public Set<String> getNonNullEntryNames() {
    if (uniqueNonNullEntryNames == null) {
      compileEntryNameSet();
    }

    return uniqueNonNullEntryNames;
  }

  private void parseManifestContent() {
    log.debug("Parsing ASiCArchiveManifest from manifest document: {}", manifestDocument);
    Element rootElement = loadManifestRootElement(manifestDocument);

    referencedTimestamp = new Reference(DomUtils.getElement(rootElement, ASiCManifestPath.SIG_REFERENCE_PATH));

    referencedDataObjects = Optional
            .ofNullable(DomUtils.getNodeList(rootElement, ASiCManifestPath.DATA_OBJECT_REFERENCE_PATH))
            .filter(nodeList -> nodeList.getLength() > 0)
            .map(nodeList -> IntStream
                    .range(0, nodeList.getLength())
                    .mapToObj(nodeList::item)
                    .filter(Element.class::isInstance)
                    .map(Element.class::cast)
                    .map(DataReference::new)
                    .collect(Collectors.toList())
            )
            .map(Collections::unmodifiableList)
            .orElseGet(Collections::emptyList);
  }

  private void compileEntryNameSet() {
    uniqueNonNullEntryNames = Collections.unmodifiableSet(
            getReferencedDataObjects().stream()
                    .map(Reference::getName)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet())
    );
  }

  private static Element loadManifestRootElement(DSSDocument manifestDocument) {
    try {
      Document manifestDom = DomUtils.buildDOM(manifestDocument);
      return DomUtils.getElement(manifestDom, ASiCManifestPath.ASIC_MANIFEST_PATH);
    } catch (Exception e) {
      throw new TechnicalException("Failed to parse manifest file: " + manifestDocument.getName(), e);
    }
  }

  public static class Reference {

    private final String uri;
    private final String mimeType;

    Reference(Element element) {
      uri = getAttributeIfPresent(element, ASiCManifestAttribute.URI);
      mimeType = getAttributeIfPresent(element, ASiCManifestAttribute.MIME_TYPE);
    }

    public String getUri() {
      return uri;
    }

    public String getMimeType() {
      return mimeType;
    }

    public String getName() {
      return Optional
              .ofNullable(getUri())
              .map(DSSUtils::decodeURI)
              .orElse(null);
    }

  }

  public static class DataReference extends Reference {

    private final String digestAlgorithm;
    private final String digestValue;

    DataReference(Element element) {
      super(element);

      digestAlgorithm = getValueIfPresent(element, XMLDSigPath.DIGEST_METHOD_ALGORITHM_PATH);
      digestValue = getValueIfPresent(element, XMLDSigPath.DIGEST_VALUE_PATH + "/text()");
    }

    public String getDigestAlgorithm() {
      return digestAlgorithm;
    }

    public String getDigestValue() {
      return digestValue;
    }

  }

  private static String getAttributeIfPresent(Element element, DSSAttribute attribute) {
    if (element == null || attribute == null) {
      return null;
    }
    String attributeName = attribute.getAttributeName();
    return element.hasAttribute(attributeName)
            ? element.getAttribute(attributeName)
            : null;
  }

  private static String getValueIfPresent(Element element, String xPathString) {
    if (element == null || xPathString == null) {
      return null;
    }
    try {
      return Optional
              .ofNullable(DomUtils.getNode(element, xPathString))
              .map(Node::getNodeValue)
              .orElse(null);
    } catch (Exception e) {
      log.debug("Failed to query value for '{}'", xPathString, e);
      return null;
    }
  }

}
