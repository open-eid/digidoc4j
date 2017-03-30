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

import java.io.IOException;
import java.io.InputStream;
import java.util.ServiceLoader;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.bdoc.ExistingBDocContainer;
import org.digidoc4j.impl.ddoc.DDocOpener;
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
  private final static ServiceLoader< OpenableContainer > containerOpeners = ServiceLoader.load( OpenableContainer.class );

  /**
   * Open container from a file. Use {@link ContainerBuilder#fromExistingFile(String)} instead.
   *
   * @param path          file name and path.
   * @param configuration configuration settings
   * @return container new container of the specified format
   * @throws DigiDoc4JException when the file is not found or empty
   * @see ContainerBuilder
   */
  public static <T extends BaseContainer> T open(String path, Configuration configuration) throws DigiDoc4JException {
    logger.debug("Opening container from path: " + path);

    for (OpenableContainer containerOpener : containerOpeners) {
      if (containerOpener.canOpen(path)) {
        logger.debug("Found container handler");
        Object container = containerOpener.open(path, configuration);
        try {
          return (T) container;
        } catch (ClassCastException ex) {
          logger.debug("Invalid return type provided for " + container.getClass().getName());
        }
      }
    }

    String message = "Could not find suitable container handler";
    logger.debug(message);
    throw new UnsupportedFormatException(message);
  }

  /**
   * Open container from a file. Use {@link ContainerBuilder#fromExistingFile(String)} instead.
   *
   * @param path file name and path.
   * @return container
   * @throws DigiDoc4JException when the file is not found or empty
   * @see ContainerBuilder
   */
  public static <T extends BaseContainer> T open(String path) throws DigiDoc4JException {
    logger.debug("");
    return (T) open(path, Configuration.getInstance());
  }

  /**
   * Open container from a stream. Use {@link ContainerBuilder#fromStream(InputStream)} instead.
   *
   * @param inputStream                 input stream
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @return container
   * @see Configuration#isBigFilesSupportEnabled() returns true used for BDOC
   * @see ContainerBuilder
   */
  public static Container open(InputStream inputStream, boolean actAsBigFilesSupportEnabled) {
    logger.debug("Opening container from stream");
    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    try {
      if (Helper.isZipFile(inputStream)) {
        //TODO support big file support flag
        return new ExistingBDocContainer(inputStream);
      } else {
        return new DDocOpener().open(inputStream);
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(inputStream);
    }
  }

  /**
   * Open container from a stream. Use {@link ContainerBuilder#fromStream(InputStream)} instead.
   *
   * @param inputStream stream of a container to open.
   * @param configuration configuration settings.
   * @return opened container.
   * @see ContainerBuilder
   */
  public static <T extends BaseContainer> T open(InputStream inputStream, Configuration configuration) throws DigiDoc4JException {
    logger.debug("Opening container from stream");

    inputStream = Helper.ensureResettableBufferedInputStream(inputStream);

    for (OpenableContainer containerOpener : containerOpeners) {
      if (containerOpener.canOpen(inputStream)) {
        logger.debug("Found container handler");
        Object container = containerOpener.open(inputStream, configuration);
        try {
          return (T) container;
        } catch (ClassCastException ex) {
          logger.debug("Invalid return type provided for " + container.getClass().getName());
        }

        Helper.tryResetInputStream(inputStream);
      }
    }

    String message = "Could not find suitable container handler";
    logger.debug(message);
    throw new UnsupportedFormatException(message);
  }

  private static Container openBDocContainer(String path, Configuration configuration) {
    configuration.loadConfiguration("digidoc4j.yaml");
    return new ExistingBDocContainer(path, configuration);
  }
}
