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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.AsicFileContainerParser;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicStreamContainerParser;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asics.AsicSCompositeContainer;
import org.digidoc4j.impl.asic.asics.AsicSContainer;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.digidoc4j.impl.ddoc.DDocOpener;
import org.digidoc4j.impl.pades.PadesContainer;
import org.digidoc4j.utils.ContainerUtils;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * Helper class for opening containers. The proper way of opening containers would be using {@link ContainerBuilder},
 * for example using {@link ContainerBuilder#fromExistingFile(String)} and {@link ContainerBuilder#fromStream(InputStream)}.
 *
 * @see ContainerBuilder
 */
public class ContainerOpener {

  private static final int MAX_LEVEL_OF_NESTED_CONTAINERS = 1;

  private static final Logger logger = LoggerFactory.getLogger(ContainerOpener.class);

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
      if (Helper.isPdfFile(path)){
        return openPadesContainer(path, configuration);
      } else if (Helper.isZipFile(new File(path))) {
        return openAsicContainer(path, configuration, 0);
      } else {
        return new DDocOpener().open(path, configuration);
      }
    } catch (EOFException eof) {
      throw new DigiDoc4JException("File is invalid");
    } catch (IOException e) {
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
    return open(path, Configuration.getInstance());
  }

  /**
   * Open container from a stream. Use {@link ContainerBuilder#fromStream(InputStream)} instead.
   *
   * @param stream                      input stream
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @return container
   * @see ContainerBuilder
   */
  public static Container open(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    return open(stream, Configuration.getInstance());
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
    try (BufferedInputStream bufferedInputStream = new BufferedInputStream(stream)) {
      if (Helper.isZipFile(bufferedInputStream)) {
        return openAsicContainer(bufferedInputStream, configuration, 0);
      } else {
        return new DDocOpener().open(bufferedInputStream, configuration);
      }
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
  }

  private static Container openAsicContainer(String path, Configuration configuration, int currentRecursionDepth) {
    configuration.loadConfiguration("digidoc4j.yaml", false);
    AsicParseResult parseResult = new AsicFileContainerParser(path, configuration).read();
    if (isAsicSContainer(parseResult)){
      return openAsicSContainer(parseResult, configuration, currentRecursionDepth);
    }
    if (isBDocContainer(parseResult)) {
      return new BDocContainer(parseResult, configuration);
    }

    return new AsicEContainer(parseResult, configuration);
  }

  private static Container openAsicContainer(InputStream stream, Configuration configuration, int currentRecursionDepth) {
    AsicParseResult parseResult = new AsicStreamContainerParser(stream, configuration).read();
    if (isAsicSContainer(parseResult)){
      return openAsicSContainer(parseResult, configuration, currentRecursionDepth);
    }
    if (isBDocContainer(parseResult)) {
      return new BDocContainer(parseResult, configuration);
    }

    return new AsicEContainer(parseResult, configuration);
  }

  private static Container openAsicSContainer(AsicParseResult parseResult, Configuration configuration, int currentRecursionDepth) {
    if (currentRecursionDepth < MAX_LEVEL_OF_NESTED_CONTAINERS && isValidTimestampedContainer(parseResult)) {
      DataFile potentialNestedContainer = parseResult.getDataFiles().get(0);
      Container nestedContainer = null;

      if (ContainerUtils.isAsicContainer(potentialNestedContainer::getStream,
              MimeTypeEnum.ASICE.getMimeTypeString(), MimeTypeEnum.ASICS.getMimeTypeString())) {
        try (InputStream inputStream = potentialNestedContainer.getStream()) {
          nestedContainer = openAsicContainer(inputStream, configuration, currentRecursionDepth + 1);
        } catch (Exception e) {
          throw new TechnicalException("Failed to parse nested ASiC container", e);
        }
      } else {
        try (InputStream inputStream = potentialNestedContainer.getStream()) {
          nestedContainer = new DDocOpener().open(inputStream, configuration);
        } catch (Exception e) {
          logger.trace("Failed to open data file as nested DDOC container", e);
        }
      }

      if (nestedContainer != null) {
        return new AsicSCompositeContainer(parseResult, nestedContainer, configuration);
      }
    }
    return new AsicSContainer(parseResult, configuration);
  }

  private static Container openPadesContainer(String path, Configuration configuration) {
    configuration.loadConfiguration("digidoc4j.yaml", false);
    return new PadesContainer(configuration, path);
  }

  private static boolean isAsicSContainer(AsicParseResult parseResult) {
    return parseResult.getMimeType().equals(MimeTypeEnum.ASICS.getMimeTypeString());
  }

  private static boolean isValidTimestampedContainer(AsicParseResult parseResult) {
    return CollectionUtils.size(parseResult.getDataFiles()) == 1 // Must contain exactly 1 datafile
            && CollectionUtils.isEmpty(parseResult.getSignatures()) // Must not be signed
            && CollectionUtils.isNotEmpty(parseResult.getTimestamps()); // Must have timestamp tokens
  }

  private static boolean isBDocContainer(AsicParseResult parseResult) {
    return hasBDocOnlySignature(parseResult.getSignatures());
  }

  private static boolean hasBDocOnlySignature(List<XadesSignatureWrapper> signatureWrappers) {
    for (XadesSignatureWrapper signatureWrapper : signatureWrappers) {
      if (SignatureContainerMatcherValidator.isBDocOnlySignature(signatureWrapper.getSignature().getProfile())) {
        return true;
      }
    }

    return false;
  }

}
