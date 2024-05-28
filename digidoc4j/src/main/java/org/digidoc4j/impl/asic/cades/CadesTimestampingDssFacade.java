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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESLevelBaselineLTA;
import eu.europa.esig.dss.asic.cades.timestamp.ASiCWithCAdESTimestampService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Container;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Facade class for DSS CAdES timestamping functionality for ASiC containers.
 */
public class CadesTimestampingDssFacade {

  private static final String SOMETHING_WENT_WRONG_PREFIX = "Something went wrong with timestamping: ";
  private static final Logger log = LoggerFactory.getLogger(CadesTimestampingDssFacade.class);

  private final CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
  private final ASiCWithCAdESFilenameFactory filenameFactory = new DefaultASiCWithCAdESFilenameFactory();
  private final ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
  private eu.europa.esig.dss.enumerations.DigestAlgorithm referenceDigestAlgorithm;
  private TSPSource tspSource;

  /**
   * Creates a timestamp that covers the specified list of container datafiles and the specified list of previously
   * existing timestamps.
   * Existing timestamp tokens, if any, will also be covered by the new timestamp token that this finalizer will create.
   * NB: timestamping process <b>may</b> also <b>augment</b> (some of) the existing timestamps presented in the list of
   * existing timestamps.
   *
   * @param dataFiles list of datafiles to cover by the new timestamp
   * @param timestamps list of previous timestamps to cover by the new timestamp
   * @return collection of documents representing the newly created timestamp
   */
  public TimestampDocumentsHolder timestampContent(List<DSSDocument> dataFiles, List<UpdateableTimestampDocumentsHolder> timestamps) {
    ASiCContent asicContent = createAsicContent();
    asicContent.getSignedDocuments().addAll(dataFiles);

    if (CollectionUtils.isEmpty(timestamps)) {
      return new TimestampDocumentsHolder(timestampAsicContent(asicContent));
    } else {
      return extendContainerTimestamps(asicContent, timestamps);
    }
  }

  /**
   * Configures this facade to create timestamps for the specified container type.
   * Supported container types:
   * <ul>
   *     <li>{@link Container.DocumentType#ASICE}</li>
   *     <li>{@link Container.DocumentType#ASICS}</li>
   * </ul>
   *
   * @param type container type to use
   */
  public void setContainerType(Container.DocumentType type) {
    switch (type) {
      case ASICE:
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        timestampParameters.aSiC().setMimeType(MimeTypeEnum.ASICE.getMimeTypeString());
        break;
      case ASICS:
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        timestampParameters.aSiC().setMimeType(MimeTypeEnum.ASICS.getMimeTypeString());
        break;
      default:
        throw new NotSupportedException("Unsupported container type: " + type);
    }
  }

  /**
   * Configures this facade to create timestamps using the specified digest algorithm.
   *
   * @param digestAlgorithm timestamp digest algorithm to use
   */
  public void setTimestampDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    timestampParameters.setDigestAlgorithm(digestAlgorithm.getDssDigestAlgorithm());
  }

  /**
   * Configures this facade to hash references using the specified digest algorithm.
   *
   * @param digestAlgorithm reference digest algorithm to use
   */
  public void setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    referenceDigestAlgorithm = digestAlgorithm.getDssDigestAlgorithm();
  }

  /**
   * Configures this facade to use the specified {@link AIASource} for timestamping process.
   *
   * @param aiaSource an instance of {@link AIASource} to use
   */
  public void setAiaSource(AIASource aiaSource) {
    certificateVerifier.setAIASource(aiaSource);
  }

  /**
   * Configures this facade to use the specified {@link CertificateSource} as a trusted certificate source.
   *
   * @param certificateSource an instance of {@link CertificateSource} to use
   */
  public void setCertificateSource(CertificateSource certificateSource) {
    if (certificateSource == null || certificateSource instanceof ListCertificateSource) {
      certificateVerifier.setTrustedCertSources((ListCertificateSource) certificateSource);
    } else {
      certificateVerifier.setTrustedCertSources(certificateSource);
    }
  }

  /**
   * Configures this facade to use the specified {@link OCSPSource} for timestamping process.
   *
   * @param ocspSource an instance of {@link OCSPSource} to use
   */
  public void setOcspSource(OCSPSource ocspSource) {
    certificateVerifier.setOcspSource(ocspSource);
  }

  /**
   * Configures this facade to use the specified {@link TSPSource} for timestamping process.
   *
   * @param tspSource an instance of {@link OCSPSource} to use
   */
  public void setTspSource(TSPSource tspSource) {
    this.tspSource = tspSource;
  }

  private ASiCContent createAsicContent() {
    ASiCContent asicContent = new ASiCContent();
    asicContent.setContainerType(timestampParameters.aSiC().getContainerType());
    return asicContent;
  }

  private DSSDocument timestampAsicContent(ASiCContent asicContent) {
    ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(
            Objects.requireNonNull(tspSource, "TSP source cannot be null"),
            Objects.requireNonNull(filenameFactory, "Filename factory cannot be null")
    );

    asicContent = timestampService.timestamp(asicContent, timestampParameters);

    if (CollectionUtils.size(asicContent.getTimestampDocuments()) != 1) {
      throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "exactly one timestamp token expected, " +
              CollectionUtils.size(asicContent.getTimestampDocuments()) + " found");
    } else if (CollectionUtils.isNotEmpty(asicContent.getAllManifestDocuments())) {
      throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "no timestamp manifests expected, " +
              CollectionUtils.size(asicContent.getAllManifestDocuments()) + " found");
    }

    return asicContent.getTimestampDocuments().get(0);
  }

  private TimestampDocumentsHolder extendContainerTimestamps(ASiCContent asicContent, List<UpdateableTimestampDocumentsHolder> timestamps) {
    ASiCWithCAdESLevelBaselineLTA extensionService = new ASiCWithCAdESLevelBaselineLTA(
            certificateVerifier,
            Objects.requireNonNull(tspSource, "TSP source cannot be null"),
            Objects.requireNonNull(filenameFactory, "Filename factory cannot be null")
    );

    Mappings mappings = new Mappings(timestamps);
    asicContent.getTimestampDocuments().addAll(mappings.getTimestampDocuments());
    asicContent.getArchiveManifestDocuments().addAll(mappings.getArchiveManifestDocuments());

    if (referenceDigestAlgorithm != null) {
      asicContent = extensionService.extend(asicContent, createSignatureParameters());
    } else {
      asicContent = extensionService.extend(asicContent, timestampParameters.getDigestAlgorithm());
    }

    if (CollectionUtils.size(asicContent.getTimestampDocuments()) != mappings.getTimestampCount() + 1) {
      throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + (mappings.getTimestampCount() + 1) +
              " timestamp tokens expected, " + CollectionUtils.size(asicContent.getTimestampDocuments()) + " found");
    } else if (CollectionUtils.size(asicContent.getAllManifestDocuments()) != mappings.getArchiveManifestCount() + 1) {
      throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + (mappings.getArchiveManifestCount() + 1) +
              " timestamp manifests expected, " + CollectionUtils.size(asicContent.getAllManifestDocuments()) + " found");
    }

    TimestampDocumentsHolder timestampDocumentsHolder = new TimestampDocumentsHolder(
            mappings.getNewTimestampDocument(asicContent.getTimestampDocuments())
    );
    timestampDocumentsHolder.setManifestDocument(
            mappings.getNewArchiveManifestDocument(asicContent.getArchiveManifestDocuments())
    );
    mappings.processTimestampOverrides(asicContent.getTimestampDocuments());
    return timestampDocumentsHolder;
  }

  private CAdESSignatureParameters createSignatureParameters() {
    CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
    signatureParameters.setArchiveTimestampParameters(timestampParameters);
    if (referenceDigestAlgorithm != null) {
      signatureParameters.setReferenceDigestAlgorithm(referenceDigestAlgorithm);
    } else if (timestampParameters.getDigestAlgorithm() != null) {
      signatureParameters.setReferenceDigestAlgorithm(timestampParameters.getDigestAlgorithm());
    }
    return signatureParameters;
  }

  private static class Mappings {

    private final Map<String, DssDocumentWrapper> timestampMappings = new LinkedHashMap<>();
    private final Map<String, Consumer<DSSDocument>> timestampOverrideListeners = new HashMap<>();
    private final Set<DssDocumentWrapper> archiveManifests = new LinkedHashSet<>();

    public Mappings(List<UpdateableTimestampDocumentsHolder> timestamps) {
      for (UpdateableTimestampDocumentsHolder timestamp : timestamps) {
        DSSDocument timestampDocument = timestamp.getTimestampDocument();
        DssDocumentWrapper timestampWrapper = new DssDocumentWrapper(timestampDocument);
        timestampMappings.put(timestampDocument.getName(), timestampWrapper);

        DSSDocument archiveManifestDocument = timestamp.getManifestDocument();
        if (archiveManifestDocument != null) {
          DssDocumentWrapper archiveManifestWrapper = new DssDocumentWrapper(archiveManifestDocument);
          archiveManifests.add(archiveManifestWrapper);
        }

        Consumer<DSSDocument> timestampOverrideListener = timestamp.getTimestampDocumentOverrideListener();
        if (timestampOverrideListener != null) {
          timestampOverrideListeners.put(timestampDocument.getName(), timestampOverrideListener);
        } else {
          log.warn("No timestamp override listener found for '{}'", timestampDocument.getName());
        }
      }
    }

    public DSSDocument getNewTimestampDocument(List<DSSDocument> documents) {
      List<DSSDocument> newDocuments = documents.stream()
              .filter(d -> !timestampMappings.containsKey(d.getName()))
              .collect(Collectors.toList());

      if (CollectionUtils.size(newDocuments) == 1) {
        return newDocuments.get(0);
      } else if (CollectionUtils.isEmpty(newDocuments)) {
        throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "no new timestamp tokens found");
      } else {
        throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "exactly 1 new timestamp token expected, " +
                CollectionUtils.size(newDocuments) + " found");
      }
    }

    public Collection<DSSDocument> getTimestampDocuments() {
      return Collections.unmodifiableCollection(timestampMappings.values());
    }

    public int getTimestampCount() {
      return timestampMappings.size();
    }

    public DSSDocument getNewArchiveManifestDocument(List<DSSDocument> documents) {
      List<DSSDocument> newDocuments = documents.stream()
              .filter(d -> !archiveManifests.contains(d))
              .collect(Collectors.toList());

      if (CollectionUtils.size(newDocuments) == 1) {
        return newDocuments.get(0);
      } else if (CollectionUtils.isEmpty(newDocuments)) {
        throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "no new timestamp manifests found");
      } else {
        throw new TechnicalException(SOMETHING_WENT_WRONG_PREFIX + "exactly 1 new timestamp manifest expected, " +
                CollectionUtils.size(newDocuments) + " found");
      }
    }

    public Collection<DSSDocument> getArchiveManifestDocuments() {
      return Collections.unmodifiableCollection(archiveManifests);
    }

    public int getArchiveManifestCount() {
      return archiveManifests.size();
    }

    public void processTimestampOverrides(List<DSSDocument> documents) {
      for (DSSDocument document : documents) {
        String documentName = document.getName();

        DssDocumentWrapper documentWrapper = timestampMappings.get(documentName);
        if (documentWrapper == null || document == documentWrapper) {
          continue;
        }

        Consumer<DSSDocument> timestampOverrideListener = timestampOverrideListeners.get(documentName);
        if (timestampOverrideListener == null) {
          log.warn("No timestamp override listener found for '{}'", documentName);
          continue;
        }

        log.trace("Overriding document content for timestamp: {}", documentName);
        timestampOverrideListener.accept(document);
      }
    }

  }

}
