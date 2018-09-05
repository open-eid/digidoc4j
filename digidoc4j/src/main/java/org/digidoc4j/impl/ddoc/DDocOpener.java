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

import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.factory.DigiDocFactory;
import org.digidoc4j.ddoc.factory.SAXDigiDocFactory;


public class DDocOpener implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(DDocOpener.class);
  private String temporaryDirectoryPath;

  public DDocContainer open(String path) {
    return open(path, Configuration.getInstance());
  }

  public DDocContainer open(String fileName, Configuration configuration) {
    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(ch.qos.logback.classic.Level.INFO);

    logger.info("Opening DDoc container from file: " + fileName);
    DDocFacade facade = new DDocFacade(configuration);
    ArrayList<DigiDocException> containerOpeningExceptions = new ArrayList<>();
    SignedDoc signedDoc = openSignedDoc(fileName, containerOpeningExceptions);
    validateOpenedContainerExceptions(containerOpeningExceptions);
    facade.setContainerOpeningExceptions(containerOpeningExceptions);
    return createContainer(facade, signedDoc);
  }

  public DDocContainer open(InputStream stream) {
    return open(stream, Configuration.getInstance());
  }

  public DDocContainer open(InputStream stream, Configuration configuration) {
    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger)LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(ch.qos.logback.classic.Level.INFO);

    logger.info("Opening DDoc from stream");
    DDocFacade facade = new DDocFacade(configuration);
    ArrayList<DigiDocException> containerOpeningExceptions = new ArrayList<>();
    SignedDoc signedDoc = openSignedDoc(stream, containerOpeningExceptions);
    validateOpenedContainerExceptions(containerOpeningExceptions);
    facade.setContainerOpeningExceptions(containerOpeningExceptions);
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

  private SignedDoc openSignedDoc(InputStream stream, ArrayList<DigiDocException> openContainerExceptions) throws DigiDoc4JException {
    try {
      DigiDocFactory digFac = createDigiDocFactory();
      SignedDoc signedDoc = digFac.readSignedDocFromStreamOfType(stream, false, openContainerExceptions);
      logger.info("DDoc container opened from stream");
      return signedDoc;
    } catch (DigiDocException e) {
      logger.error("Failed to open DDoc from stream: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private DigiDocFactory createDigiDocFactory() {
    DigiDocFactory digFac = new SAXDigiDocFactory();
    if (StringUtils.isNotBlank(temporaryDirectoryPath)) {
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
      if (openContainerException.getCode() == DigiDocException.ERR_PARSE_XML
          && openContainerException.getMessage() != null
          && openContainerException.getMessage().contains("Invalid xml file")) {
        exception = new DigiDocException(DigiDocException.ERR_PARSE_XML,
            "Invalid input file format.", openContainerException.getNestedException());
      } else {
        exception = openContainerException;
      }
    }
    return exception;
  }

  private DDocContainer createContainer(DDocFacade facade, SignedDoc signedDoc) {
    facade.setSignedDoc(signedDoc);
    return new DDocContainer(facade);
  }
}
