package org.digidoc4j.impl.bdoc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.OpenableContainer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.CharMatcher;

import eu.europa.esig.dss.MimeType;

/**
 * Created by Kaarel Raspel on 21/03/17.
 */
public class BDocContainerOpener implements OpenableContainer {

  private final static Logger logger = LoggerFactory.getLogger(BDocContainerOpener.class);

  @Override
  public boolean canOpen(InputStream inputStream) {
    logger.debug("Verifying container from stream");

    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    try {
      if (!Helper.isZipFile(inputStream)) {
        logger.debug("Not a zip file");
        return false;
      }

      String mimetype = getMimeTypeFromZip(inputStream);
      return mimetype != null && mimetype.equalsIgnoreCase(MimeType.ASICE.getMimeTypeString());
    } catch (IOException e) {
      logger.error(e.getMessage());
      return false;
    } finally {
      Helper.tryResetInputStream(inputStream);
    }
  }

  @Override
  public boolean canOpen(String containerPath) {
    logger.debug("Verifying container from file");

    try (FileInputStream fileInputStream = new FileInputStream(containerPath)) {
      return canOpen(fileInputStream);
    } catch (IOException e) {
      logger.error(e.getMessage());
      return false;
    }
  }

  @Override
  public BDocContainer open(InputStream inputStream) {
    return open(inputStream, Configuration.getInstance());
  }

  @Override
  public BDocContainer open(String containerPath) {
    return open(containerPath, Configuration.getInstance());
  }

  @Override
  public BDocContainer open(InputStream inputStream, Configuration configuration) {
    return new ExistingBDocContainer(inputStream, configuration);
  }

  @Override
  public BDocContainer open(String containerPath, Configuration configuration) {
    try {
      return open(new FileInputStream(containerPath), configuration);
    } catch (FileNotFoundException ex) {
      throw new DigiDoc4JException(ex);
    }
  }

  public static String getMimeTypeFromZip(InputStream inputStream) throws IOException {
    String mimetype = null;

    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    ZipEntry zipEntry;
    ZipInputStream zipInputStream = new ZipInputStream(inputStream);
    while ((zipEntry = zipInputStream.getNextEntry()) != null) {
      if (!zipEntry.isDirectory() && zipEntry.getName().equalsIgnoreCase("mimetype")) {
        mimetype = IOUtils.toString(zipInputStream);
        mimetype = CharMatcher.ASCII.negate().removeFrom(mimetype);
        break;
      }
    }

    Helper.tryResetInputStream(inputStream);

    return mimetype;
  }
}
