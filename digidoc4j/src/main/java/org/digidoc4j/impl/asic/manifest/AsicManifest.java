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

import eu.europa.esig.dss.asic.xades.definition.ManifestAttribute;
import eu.europa.esig.dss.asic.xades.definition.ManifestElement;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Collection;

/**
 * Represents the META-INF/manifest.xml sub-document
 */
public class AsicManifest {

  private static final Logger logger = LoggerFactory.getLogger(AsicManifest.class);

  public static final String XML_PATH = "META-INF/manifest.xml";

  private final Document dom;
  private final Element manifestElement;

  /**
   * Creates an instance of ASiC manifest without specifying container type
   * (the root file entry mimetype defaults to {@link MimeTypeEnum#ASICE}).
   */
  public AsicManifest() {
    this(null);
  }

  /**
   * Creates an instance of ASiC manifest with the specified container type.
   * Container type {@link Constant#ASICS_CONTAINER_TYPE} sets the root file entry mimetype as
   * {@link MimeTypeEnum#ASICS}, any other value makes the root file entry mimetype to default to
   * {@link MimeTypeEnum#ASICE}.
   *
   * @param containerType the container type
   */
  public AsicManifest(String containerType) {
    logger.debug("Creating new manifest");
    dom = DomUtils.buildDOM();

    manifestElement = DomUtils.createElementNS(dom, ManifestNamespace.NS, ManifestElement.MANIFEST);
    DomUtils.setAttributeNS(manifestElement, ManifestNamespace.NS, ManifestAttribute.VERSION, "1.2");
    dom.appendChild(manifestElement);

    Element entryElement = DomUtils.addElement(dom, manifestElement, ManifestNamespace.NS, ManifestElement.FILE_ENTRY);
    DomUtils.setAttributeNS(entryElement, ManifestNamespace.NS, ManifestAttribute.FULL_PATH, "/");
    if (Constant.ASICS_CONTAINER_TYPE.equals(containerType)) {
      DomUtils.setAttributeNS(entryElement, ManifestNamespace.NS, ManifestAttribute.MEDIA_TYPE, MimeTypeEnum.ASICS.getMimeTypeString());
    } else {
      DomUtils.setAttributeNS(entryElement, ManifestNamespace.NS, ManifestAttribute.MEDIA_TYPE, MimeTypeEnum.ASICE.getMimeTypeString());
    }
  }

  /**
   * Adds a list of file entries, representing the specified data files, into this manifest file.
   *
   * @param dataFiles the list of data files to add file entries for
   *
   * @deprecated Use {@link #addFileEntries(Collection)} instead.
   */
  @Deprecated
  public void addFileEntry(Collection<DataFile> dataFiles) {
    addFileEntries(dataFiles);
  }

  /**
   * Adds a list of file entries, representing the specified data files, into this manifest file.
   *
   * @param dataFiles the list of data files to add file entries for
   */
  public void addFileEntries(Collection<DataFile> dataFiles) {
    dataFiles.forEach(this::addFileEntry);
  }

  /**
   * Adds a new file entry, representing the specified data file, into this manifest file.
   *
   * @param dataFile the data file to add a new file entry for
   */
  public void addFileEntry(DataFile dataFile) {
    logger.debug("Adding " + dataFile.getName() + " to manifest");
    Element entryElement = DomUtils.addElement(dom, manifestElement, ManifestNamespace.NS, ManifestElement.FILE_ENTRY);
    DomUtils.setAttributeNS(entryElement, ManifestNamespace.NS, ManifestAttribute.MEDIA_TYPE, dataFile.getMediaType());
    DomUtils.setAttributeNS(entryElement, ManifestNamespace.NS, ManifestAttribute.FULL_PATH, dataFile.getName());
  }

  /**
   * Returns the bytes of the current state of this manifest file.
   *
   * @return the bytes of the current state of this manifest file
   */
  public byte[] getBytes() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    writeTo(outputStream);
    return outputStream.toByteArray();
  }

  /**
   * Writes the bytes of the current state of this manifest file into the specified output stream.
   *
   * @param outputStream the output stream to write the bytes of this manifest files into
   */
  public void writeTo(OutputStream outputStream) {
    DomUtils.writeDocumentTo(dom, outputStream);
  }

}
