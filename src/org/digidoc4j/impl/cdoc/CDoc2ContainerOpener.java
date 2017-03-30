package org.digidoc4j.impl.cdoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.OpenableContainer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.BDocContainerOpener;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Kaarel Raspel on 22/03/17.
 */
public class CDoc2ContainerOpener implements OpenableContainer {

  private final static Logger logger = LoggerFactory.getLogger(CDoc2ContainerOpener.class);

  @Override
  public boolean canOpen(String filename) {
    logger.debug("Verifying container from file");

    try (FileInputStream fileInputStream = new FileInputStream(filename)) {
      return canOpen(fileInputStream);
    } catch (IOException e) {
      logger.error(e.getMessage());
      return false;
    }
  }

  @Override
  public boolean canOpen(InputStream inputStream) {
    logger.debug("Verifying container from stream");

    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    try {
      if (!Helper.isZipFile(inputStream)) {
        logger.debug("Not a zip file");
        return false;
      }

      String mimetype = BDocContainerOpener.getMimeTypeFromZip(inputStream);
      return mimetype != null && mimetype.equals(CDoc2Container.MimeType.getMimeTypeString());
    } catch (IOException e) {
      logger.error(e.getMessage());
      return false;
    } finally {
      Helper.tryResetInputStream(inputStream);
    }
  }

  @Override
  public CDoc2Container open(InputStream is) {
    return open(is, Configuration.getInstance());
  }

  @Override
  public CDoc2Container open(String containerPath) {
    return open(containerPath, Configuration.getInstance());
  }

  @Override
  public CDoc2Container open(InputStream inputStream, Configuration configuration) {
    return new ExistingCDoc2Container(inputStream, configuration);
  }

  @Override
  public CDoc2Container open(String containerPath, Configuration configuration) {
    try (FileInputStream fileInputStream = new FileInputStream(new File(containerPath))) {
      return open(fileInputStream, configuration);
    } catch (IOException ex) {
      throw new DigiDoc4JException("Could not open CDoc 2.0", ex);
    }
  }
}
