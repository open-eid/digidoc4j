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

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicESignatureFinalizer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureFinalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;

/**
 * Builder for creating a signature finalizer for finalizing signing process.
 */
public final class SignatureFinalizerBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(SignatureFinalizerBuilder.class);

  /**
   * Create a new signature finalizer based on a container and signature parameters.
   * Container type is used to determine which type of signature finalizer should be created.
   *
   * @param container container to be signed.
   * @param signatureParameters signature parameters. These are related to the signing location and signer roles
   * @return finalizer for creating a signature.
   */
  public static SignatureFinalizer aFinalizer(Container container, SignatureParameters signatureParameters) {
    return determineFinalizer(
            container.getDataFiles(),
            signatureParameters,
            container.getConfiguration(),
            container.getType());
  }

  /**
   * Create a new signature finalizer based on datafiles, signature parameters, configuration and document type.
   * Document type is used to determine which type of signature finalizer should be created.
   *
   * @param dataFilesToSign datafiles to be signed
   * @param signatureParameters signature parameters. These are related to the signing location and signer roles
   * @param configuration configuration context
   * @param documentType type of a document
   * @return finalizer for creating a signature
   */
  public static SignatureFinalizer aFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration, Container.DocumentType documentType) {
    return determineFinalizer(
            dataFilesToSign,
            signatureParameters,
            configuration,
            documentType.name());
  }

  private static SignatureFinalizer determineFinalizer(List<DataFile> dataFilesToSign, SignatureParameters signatureParameters, Configuration configuration, String documentType) {
    if (isDocumentOfType(documentType, BDOC.name())) {
      return new BDocSignatureFinalizer(dataFilesToSign, signatureParameters, configuration);
    } else if (isDocumentOfType(documentType, ASICE.name())) {
      return new AsicESignatureFinalizer(dataFilesToSign, signatureParameters, configuration);
    } else if (isDocumentOfType(documentType, ASICS.name())) {
      return new AsicSignatureFinalizer(dataFilesToSign, signatureParameters, configuration);
    } else {
      LOGGER.error("Unknown document type: {}", documentType);
      throw new NotSupportedException("Unknown document type: " + documentType);
    }
  }

  private static boolean isDocumentOfType(String actualDocumentType, String expectedDocumentType) {
    return StringUtils.equalsIgnoreCase(expectedDocumentType, actualDocumentType);
  }
}
