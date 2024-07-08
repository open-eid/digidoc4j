/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.apache.commons.lang3.ArrayUtils;
import org.digidoc4j.exceptions.TechnicalException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Facade class for DSS CAdES validation functionality for ASiC-S containers.
 */
public class CadesValidationDssFacade extends AbstractCadesDssFacade {

  private final ASiCContent asicContent = new ASiCContent();

  /**
   * Sets the list of datafiles to be used for the next validation event (next call to {@link #openValidator()}).
   *
   * @param dataFiles list of datafiles of the container to be validated
   */
  public void setDataFiles(List<DSSDocument> dataFiles) {
    asicContent.setSignedDocuments(new ArrayList<>(dataFiles));
  }

  /**
   * Sets the list of timestamps to be used for the next validation event (next call to {@link #openValidator()}).
   *
   * @param timestamps list of timestamps of the container to be validated
   */
  public void setTimestamps(List<TimestampDocumentsHolder> timestamps) {
    List<DSSDocument> timestampDocuments = new ArrayList<>();
    List<DSSDocument> archiveManifestDocuments = new ArrayList<>();

    for (TimestampDocumentsHolder timestamp : timestamps) {
      timestampDocuments.add(timestamp.getTimestampDocument());
      Optional
              .ofNullable(timestamp.getManifestDocument())
              .ifPresent(archiveManifestDocuments::add);
    }

    asicContent.setTimestampDocuments(timestampDocuments);
    asicContent.setArchiveManifestDocuments(archiveManifestDocuments);
  }

  /**
   * Opens and returns a signed document validator based on the current state of this validation facade.
   *
   * @return signed document validator
   */
  public SignedDocumentValidator openValidator() {
    ASiCContainerWithCAdESValidator containerValidator = new ASiCContainerWithCAdESValidator(asicContent);
    containerValidator.setCertificateVerifier(certificateVerifier);

    return containerValidator;
  }

  @Override
  protected void setContainerType(ASiCContainerType containerType, MimeType mimeType) {
    asicContent.setAsicContainer(createDummyContainerDocument(mimeType));
    asicContent.setContainerType(Objects.requireNonNull(containerType));
    asicContent.setMimeTypeDocument(createMimeTypeDocument(mimeType));
  }

  private static DSSDocument createDummyContainerDocument(MimeType mimeType) {
    // TODO (DD4J-1076): Figure out why is this needed and document it here
    return new InMemoryDocument(ArrayUtils.EMPTY_BYTE_ARRAY, null, mimeType);
  }

  private static DSSDocument createMimeTypeDocument(MimeType mimeType) {
    return new InMemoryDocument(
            Optional
                    .ofNullable(mimeType)
                    .map(MimeType::getMimeTypeString)
                    .map(s -> s.getBytes(StandardCharsets.UTF_8))
                    .orElseThrow(() -> new TechnicalException("Container mime type not provided")),
            ASiCUtils.MIME_TYPE,
            MimeTypeEnum.BINARY
    );
  }

}
