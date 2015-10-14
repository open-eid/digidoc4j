/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.bdoc.AsicFacade;
import org.digidoc4j.impl.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.impl.ddoc.DDocFacade;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class for opening containers. The proper way of opening containers would be using {@link ContainerBuilder},
 * for example using {@link ContainerBuilder#fromExistingFile(String)} and {@link ContainerBuilder#fromStream(InputStream)}.
 *
 * @see ContainerBuilder
 */
public class ContainerOpener {

  private final static Logger logger = LoggerFactory.getLogger(ContainerOpener.class);

  /**
   * Open container from a file. Use {@link ContainerBuilder#fromExistingFile(String)} instead.
   *
   * @param path          file name and path.
   * @param configuration configuration settings
   * @return container new container of the specified format
   * @throws DigiDoc4JException when the file is not found or empty
   * @see ContainerBuilder
   */
  public static Container open(String path, Configuration configuration) throws DigiDoc4JException {
    logger.debug("Opening container from path: " + path);
    try {
      if (Helper.isZipFile(new File(path))) {
        return openBDocContainer(path, configuration);
      } else {
        DDocFacade facade = new DDocFacade(path, configuration);
        return new DDocContainer(facade);
      }
    } catch (EOFException eof) {
      String msg = "File is not valid.";
      logger.error(msg);
      throw new DigiDoc4JException(msg);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Open container from a file. Use {@link ContainerBuilder#fromExistingFile(String)} instead.
   *
   * @param path file name and path.
   * @return container
   * @throws DigiDoc4JException when the file is not found or empty
   * @see ContainerBuilder
   */
  public static Container open(String path) throws DigiDoc4JException {
    logger.debug("");
    return open(path, new Configuration());
  }

  /**
   * Open container from a stream. Use {@link ContainerBuilder#fromStream(InputStream)} instead.
   *
   * @param stream                      input stream
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @return container
   * @see Configuration#isBigFilesSupportEnabled() returns true used for BDOC
   * @see ContainerBuilder
   */
  public static Container open(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    logger.debug("Opening container from stream");
    BufferedInputStream bufferedInputStream = new BufferedInputStream(stream);

    try {
      if (Helper.isZipFile(bufferedInputStream)) {
        AsicFacade facade = new AsicFacade(bufferedInputStream, actAsBigFilesSupportEnabled);
        return new BDocContainer(facade);
      } else {
        DDocFacade facade = new DDocFacade(bufferedInputStream);
        return new DDocContainer(facade);
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(bufferedInputStream);
    }
  }

  /**
   * Open container from a stream. Use {@link ContainerBuilder#fromStream(InputStream)} instead.
   *
   * @param stream stream of a container to open.
   * @param configuration configuration settings.
   * @return opened container.
   * @see ContainerBuilder
   */
  public static Container open(InputStream stream, Configuration configuration) {
    logger.debug("Opening container from stream");
    BufferedInputStream bufferedInputStream = new BufferedInputStream(stream);

    try {
      if (Helper.isZipFile(bufferedInputStream)) {
        AsicFacade facade = new AsicFacade(bufferedInputStream, true, configuration);
        return new BDocContainer(facade);
      } else {
        DDocFacade facade = new DDocFacade(bufferedInputStream, configuration);
        return new DDocContainer(facade);
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(bufferedInputStream);
    }
  }

  private static Container openBDocContainer(String path, Configuration configuration) {
    configuration.loadConfiguration("digidoc4j.yaml");
    AsicFacade facade = new AsicFacade(path, configuration);
    return new BDocContainer(facade);
  }
}
