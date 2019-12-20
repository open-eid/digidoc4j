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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Collection;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import eu.europa.esig.dss.model.MimeType;

/**
 * Represents the META-INF/manifest.xml subdocument
 */
public class AsicManifest {

  private static final Logger logger = LoggerFactory.getLogger(AsicManifest.class);
  public static final String XML_PATH = "META-INF/manifest.xml";
  private Document dom;
  private Element rootElement;

  /**
   * creates object to create manifest files
   */
  public AsicManifest() {
    generateAsicManifest(null);
  }

  /**
   * @param containerType type
   */
  public AsicManifest(String containerType) {
    generateAsicManifest(containerType);
  }

  private void generateAsicManifest(String containerType) {
    logger.debug("Creating new manifest");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      DocumentBuilder db = dbf.newDocumentBuilder();

      dom = db.newDocument();
      rootElement = dom.createElement("manifest:manifest");
      rootElement.setAttribute("xmlns:manifest", "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0");

      Element firstChild = dom.createElement("manifest:file-entry");
      firstChild.setAttribute("manifest:full-path", "/");
      if (Constant.ASICS_CONTAINER_TYPE.equals(containerType)){
        firstChild.setAttribute("manifest:media-type", MimeType.ASICS.getMimeTypeString());
      } else{
        firstChild.setAttribute("manifest:media-type", MimeType.ASICE.getMimeTypeString());
      }

      rootElement.appendChild(firstChild);

      dom.appendChild(rootElement);

    } catch (ParserConfigurationException e) {
      logger.error(e.getMessage());
      throw new TechnicalException("Error creating manifest", e);
    }
  }

  /**
   * adds list of attachments to create manifest file
   *
   * @param dataFiles list of data files
   */
  public void addFileEntry(Collection<DataFile> dataFiles) {
    for (DataFile dataFile : dataFiles) {
      logger.debug("Adding " + dataFile.getName() + " to manifest");
      Element childElement;
      childElement = dom.createElement("manifest:file-entry");
      childElement.setAttribute("manifest:media-type", dataFile.getMediaType());
      childElement.setAttribute("manifest:full-path", dataFile.getName());
      rootElement.appendChild(childElement);
    }
  }

  public byte[] getBytes() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    writeTo(outputStream);
    return outputStream.toByteArray();
  }

  public void writeTo(OutputStream outputStream) {
    DOMImplementationLS implementation = (DOMImplementationLS) dom.getImplementation();
    LSOutput lsOutput = implementation.createLSOutput();
    lsOutput.setByteStream(outputStream);
    LSSerializer writer = implementation.createLSSerializer();
    writer.write(dom, lsOutput);
  }

}
