/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.OpenableContainer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;

public class DDocOpener implements OpenableContainer, Serializable {

  private static final Logger logger = LoggerFactory.getLogger(DDocOpener.class);
  private String temporaryDirectoryPath;

  @Override
  public boolean canOpen(InputStream inputStream) {
    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);
    try {
      return verifyByFileContent(inputStream);
    } finally {
      Helper.tryResetInputStream(inputStream);
    }
  }

  @Override
  public boolean canOpen(String containerPath) {
    return verifyByFileContent(containerPath);
  }

  @Override
  public DDocContainer open(String path) {
    return open(path, Configuration.getInstance());
  }

  @Override
  public DDocContainer open(String fileName, Configuration configuration) {
    logger.info("Opening DDoc container from file: " + fileName);
    DDocFacade facade = new DDocFacade(configuration);
    ArrayList<DigiDocException> containerOpeningExceptions = new ArrayList<>();
    SignedDoc signedDoc = openSignedDoc(fileName, containerOpeningExceptions);
    validateOpenedContainerExceptions(containerOpeningExceptions);
    facade.setContainerOpeningExceptions(containerOpeningExceptions);
    return createContainer(facade, signedDoc);
  }

  @Override
  public DDocContainer open(InputStream stream) {
    logger.info("Opening DDoc from stream");
    DDocFacade facade = new DDocFacade();
    SignedDoc signedDoc = openSignedDoc(stream);
    return createContainer(facade, signedDoc);
  }

  @Override
  public DDocContainer open(InputStream stream, Configuration configuration) {
    logger.info("Opening DDoc from stream");
    DDocFacade facade = new DDocFacade(configuration);
    SignedDoc signedDoc = openSignedDoc(stream);
    return createContainer(facade, signedDoc);
  }

  public void useTemporaryDirectoryPath(String temporaryDirectoryPath) {
    this.temporaryDirectoryPath = temporaryDirectoryPath;
  }

  private SignedDoc openSignedDoc(String fileName, ArrayList<DigiDocException> openContainerExceptions) throws DigiDoc4JException {
    try {
      DigiDocFactory digFac = createDigiDocFactory();
      boolean isBdoc = false;
      return digFac.readSignedDocOfType(fileName, isBdoc, openContainerExceptions);
    } catch (DigiDocException e) {
      logger.error("Failed to open DDoc from file " + fileName + ": " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private SignedDoc openSignedDoc(InputStream stream) throws DigiDoc4JException {
    try {
      DigiDocFactory digFac = createDigiDocFactory();
      SignedDoc signedDoc = digFac.readDigiDocFromStream(stream);
      logger.info("DDoc container opened from stream");
      return signedDoc;
    } catch (DigiDocException e) {
      logger.error("Failed to open DDoc from stream: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private DigiDocFactory createDigiDocFactory() {
    DigiDocFactory digFac = new SAXDigiDocFactory();
    if(StringUtils.isNotBlank(temporaryDirectoryPath)) {
      logger.debug("Using temporary directory " + temporaryDirectoryPath);
      digFac.setTempDir(temporaryDirectoryPath);
    }
    return digFac;
  }

  private void validateOpenedContainerExceptions(ArrayList<DigiDocException> openContainerExceptions) {
    if (SignedDoc.hasFatalErrs(openContainerExceptions)) {
      DigiDocException fatalError = getFatalError(openContainerExceptions);
      logger.error("Container has a fatal error: " + fatalError.getMessage());
      throw new DigiDoc4JException(fatalError);
    }
  }

  private DigiDocException getFatalError(List<DigiDocException> openContainerExceptions) {
    DigiDocException exception = null;
    for (DigiDocException openContainerException : openContainerExceptions) {
      if (openContainerException.getCode() == DigiDocException.ERR_PARSE_XML) {
        exception = openContainerException;
      }
    }
    return exception;
  }

  private DDocContainer createContainer(DDocFacade facade, SignedDoc signedDoc) {
    facade.setSignedDoc(signedDoc);
    return new DDocContainer(facade);
  }

  public static boolean isDDocFilename(String filename) {
    Pattern dDocPattern = Pattern.compile(".*\\.DDOC$", Pattern.CASE_INSENSITIVE);
    boolean matches = dDocPattern.matcher(filename).matches();
    return matches;
  }

  private boolean verifyByFilename(String containerPath) {
    return isDDocFilename(containerPath);
  }

  private boolean verifyByFileContent(String containerPath) {
    try (FileInputStream fileInputStream = new FileInputStream(containerPath)) {
      return verifyByFileContent(fileInputStream);
    } catch (IOException ex) {
      logger.debug(ex.getMessage(), ex);
      return false;
    }
  }

  private boolean verifyByFileContent(InputStream inputStream) {
    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    try {
      XMLStreamReader xmlStreamReader = XMLInputFactory.newInstance().createXMLStreamReader(inputStream);
      while (xmlStreamReader.hasNext()) {
        int event = xmlStreamReader.next();

        if (event == XMLStreamConstants.START_ELEMENT) {
          boolean isSignedDocRoot = xmlStreamReader.getLocalName().equalsIgnoreCase("SignedDoc");
          return isSignedDocRoot;
        }
      }
    } catch (XMLStreamException ex) {
      logger.debug("DDoc identification failed", ex);
    } finally {
      Helper.tryResetInputStream(inputStream);
    }

    return false;
  }
}
