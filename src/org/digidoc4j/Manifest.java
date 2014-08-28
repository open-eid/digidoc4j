package org.digidoc4j;

import com.sun.org.apache.xml.internal.serialize.OutputFormat;
import com.sun.org.apache.xml.internal.serialize.XMLSerializer;
import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Represents the META-INF/manifest.xml subdocument
 */
public class Manifest {

  private Document dom;
  private final Logger logger = LoggerFactory.getLogger(Manifest.class);
  private Element rootElement;

  /**
   * creates object to create manifest files
   */
  public Manifest() {
    logger.debug("");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      DocumentBuilder db = dbf.newDocumentBuilder();

      dom = db.newDocument();
      rootElement = dom.createElement("manifest:manifest");
      rootElement.setAttribute("xmlns:manifest", "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0");

      Element firstChild = dom.createElement("manifest:file-entry");
      firstChild.setAttribute("manifest:full-path", "/");
      firstChild.setAttribute("manifest:media-type", "application/vnd.etsi.asic-e+zip");
      rootElement.appendChild(firstChild);

      dom.appendChild(rootElement);

    } catch (ParserConfigurationException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * adds list of attachments to create manifest file
   *
   * @param entries list of data files
   */
  public void addFileEntry(List<DataFile> entries) {
    logger.debug("adds " + entries.size() + " entries to manifest");
    Element childElement;
    for (DataFile entry : entries) {
      childElement = dom.createElement("manifest:file-entry");
      childElement.setAttribute("manifest:media-type", entry.getMediaType());
      childElement.setAttribute("manifest:full-path", entry.getFileName());
      rootElement.appendChild(childElement);
    }
  }

  /**
   * sends manifest files to output stream
   *
   * @param out output stream
   */
  public void save(OutputStream out) {
    logger.debug("");
    XMLSerializer serializer = new XMLSerializer(out, new OutputFormat(dom));
    try {
      serializer.serialize(dom);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }
}
