/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.digidoc4j.exceptions.TechnicalException;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XmlDomCreator {

  public final static String ASICS_NS = "asic:XAdESSignatures";
  private static DocumentBuilderFactory documentBuilderFactory;

  /**
   * Creates a DOM Document object of the specified type with its document element.
   *
   * @param namespaceURI  the namespace URI of the document element to create or null
   * @param qualifiedName the qualified name of the document element to be created or null
   * @param element       document {@code Element}
   * @return {@code Document}
   */
  public static Document createDocument(final String namespaceURI, final String qualifiedName, final Element element) {
    ensureDocumentBuilder();
    try {
      DOMImplementation domImpl = documentBuilderFactory.newDocumentBuilder().getDOMImplementation();
      Document newDocument = domImpl.createDocument(namespaceURI, qualifiedName, null);
      Element newElement = newDocument.getDocumentElement();
      newDocument.adoptNode(element);
      newElement.appendChild(element);
      return newDocument;
    } catch (ParserConfigurationException e) {
      throw new TechnicalException("Failed to initialize DOM document builder factory", e);
    }
  }

  private static void ensureDocumentBuilder() {
    if (documentBuilderFactory == null) {
      initializeDocumentBuilderFactory();
    }
  }

  private static synchronized void initializeDocumentBuilderFactory() {
    //Using double-checked locking to avoid other threads to start initialization
    if(documentBuilderFactory == null) {
      documentBuilderFactory = DocumentBuilderFactory.newInstance();
      documentBuilderFactory.setNamespaceAware(true);
      try {
        // disable external entities
        documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        documentBuilderFactory.setXIncludeAware(false);
        documentBuilderFactory.setExpandEntityReferences(false);
      } catch (ParserConfigurationException e) {
        throw new TechnicalException("Failed to initialize DOM document builder factory", e);
      }
    }
  }
}
