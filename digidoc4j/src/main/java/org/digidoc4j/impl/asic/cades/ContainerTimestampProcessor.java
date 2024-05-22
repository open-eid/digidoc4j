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

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DuplicateTimestampException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TimestampNotFoundException;
import org.digidoc4j.utils.MimeTypeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * A helper class for gathering and linking timestamp tokens and their manifests, and sorting the result.
 */
public class ContainerTimestampProcessor {

  private static final Logger log = LoggerFactory.getLogger(ContainerTimestampProcessor.class);

  private final Map<String, ContainerTimestampWrapper> timestampMappings = new LinkedHashMap<>();
  private final Map<String, AsicArchiveManifest> archiveManifestMappings = new HashMap<>();

  /**
   * Adds a new CAdES timestamp into this processor as a processable timestamp.
   * The timestamp's DSSDocument must have a valid name, and no duplicates are allowed.
   *
   * @param cadesTimestamp a CAdES timestamp to add
   */
  public void addTimestamp(CadesTimestamp cadesTimestamp) {
    String timestampName = cadesTimestamp.getTimestampDocument().getName();

    if (StringUtils.isEmpty(timestampName)) {
      throw new TechnicalException("Timestamp token filename missing");
    } else if (timestampMappings.containsKey(timestampName)) {
      throw new DuplicateTimestampException("Container contains duplicate timestamp token: " + timestampName);
    }

    timestampMappings.put(timestampName, new ContainerTimestampWrapper(cadesTimestamp));
  }

  /**
   * Adds a new ASiCArchiveManifest into this processor and associates it with an existing CAdES timestamp.
   * If no timestamp with the name referenced in the provided manifest exists in this processor, then the timestamp is
   * queried via the {@code timestampResolver} callback (and is also added into this processor).
   * If the processor fails to associate the provided manifest with a timestamp (that is not yet associated with any
   * other manifest), then the method fails with an exception.
   * The manifest's DSSDocument must have a valid name, and no duplicates are allowed.
   * The contents of the provided manifest must be successfully parsable for this method to succeed.
   *
   * @param archiveManifest ASiCArchiveManifest to add into this processor and to associate with a CAdES timestamp
   * @param timestampResolver callback for finding a CAdES timestamp with a specific name; may return {@code null}
   *
   * @see #addTimestamp(CadesTimestamp)
   */
  public void addManifest(AsicArchiveManifest archiveManifest, Function<String, CadesTimestamp> timestampResolver) {
    String archiveManifestName = archiveManifest.getManifestDocument().getName();

    if (StringUtils.isEmpty(archiveManifestName)) {
      throw new TechnicalException("Timestamp manifest filename missing");
    } else if (archiveManifestMappings.containsKey(archiveManifestName)) {
      throw new DuplicateTimestampException("Container contains duplicate timestamp manifest: " + archiveManifestName);
    }

    AsicArchiveManifest.Reference referencedTimestamp = archiveManifest.getReferencedTimestamp();
    String referencedTimestampName = referencedTimestamp.getName();

    if (referencedTimestampName == null) {
      throw new TechnicalException("No timestamp reference found in manifest: " + archiveManifest.getManifestDocument().getName());
    }

    ContainerTimestampWrapper timestampWrapper = Optional
            .ofNullable(timestampMappings.get(referencedTimestampName))
            .orElseGet(() -> Optional
                    .ofNullable(timestampResolver.apply(referencedTimestampName))
                    .map(ContainerTimestampWrapper::new)
                    .orElseThrow(() -> new TimestampNotFoundException("Referenced timestamp token not found: " + referencedTimestampName)));

    if (timestampWrapper.getArchiveManifest() != null) {
      throw new DuplicateTimestampException("Timestamp token cannot be referenced by multiple ASiCArchiveManifest files");
    } else if (StringUtils.isNotBlank(referencedTimestamp.getMimeType())) {
      MimeType timestampMimeType = MimeTypeUtil.fromMimeTypeString(referencedTimestamp.getMimeType());
      timestampWrapper.getCadesTimestamp().getTimestampDocument().setMimeType(timestampMimeType);
    }

    timestampMappings.put(referencedTimestampName, timestampWrapper.withArchiveManifest(archiveManifest));
    archiveManifestMappings.put(archiveManifestName, archiveManifest);
  }

  /**
   * Tries to find the last timestamp from the set of timestamps added to this processor, and if such a timestamp exists
   * and it has an ASiCArchiveManifest associated with it, then tries to configure the mimetypes of all the entities
   * referenced by the ASiCArchiveManifest's DataObjectReference entries.
   * If the referenced entity is none of the timestamps or manifests that has already been added into this processor,
   * then {@code referenceMimeTypeListener} callback is called with the name and mimetype of that specific reference.
   * The contents of available manifests must be successfully parsable for this method to succeed.
   *
   * @param referenceMimeTypeListener callback for handling mimetype configuration for references which are not present
   * in this processor as either timestamps or ASiCArchiveManifests
   * @return {@code true} if the processor is able to determine the last timestamp, and it has a manifest associated
   * with it, otherwise {@code false}
   *
   * @see #addTimestamp(CadesTimestamp)
   * @see #addManifest(AsicArchiveManifest, Function)
   */
  public boolean resolveReferenceMimeTypes(BiConsumer<String, MimeType> referenceMimeTypeListener) {
    ContainerTimestampWrapper timestampWrapper = ContainerTimestampUtils.findLastTimestamp(timestampMappings.values());

    if (timestampWrapper == null || timestampWrapper.getArchiveManifest() == null) {
      log.debug("No ASiCArchiveManifest found to use for resolving mimetypes of timestamped entries");
      return false;
    }

    log.debug("Using '{}' for resolving reference mimetypes", timestampWrapper.getArchiveManifest().getManifestDocument().getName());
    for (AsicArchiveManifest.Reference reference : timestampWrapper.getArchiveManifest().getReferencedDataObjects()) {
      String referenceName = reference.getName();

      if (referenceName == null || StringUtils.isBlank(reference.getMimeType())) {
        continue;
      }

      MimeType referenceMimeType = MimeTypeUtil.fromMimeTypeString(reference.getMimeType());
      log.trace("Mimetype of '{}' is resolved to: {}", referenceName, reference.getMimeType());

      DSSDocument documentToConfigure = Optional
              .ofNullable(timestampMappings.get(referenceName))
              .map(ContainerTimestampWrapper::getCadesTimestamp)
              .map(CadesTimestamp::getTimestampDocument)
              .orElseGet(() -> Optional
                      .ofNullable(archiveManifestMappings.get(referenceName))
                      .map(AsicArchiveManifest::getManifestDocument)
                      .orElse(null));

      if (documentToConfigure != null) {
        documentToConfigure.setMimeType(referenceMimeType);
      } else {
        referenceMimeTypeListener.accept(referenceName, referenceMimeType);
      }
    }

    return true;
  }

  /**
   * Returns a list of timestamps and their respective manifests in the order they were added into this processor.
   *
   * @return list of timestamps and their manifests in their initial order
   *
   * @see #addTimestamp(CadesTimestamp)
   * @see #addManifest(AsicArchiveManifest, Function)
   */
  public List<ContainerTimestampWrapper> getTimestampsInInitialOrder() {
    return new ArrayList<>(timestampMappings.values());
  }

  /**
   * Tries to sort all the timestamps added into this processor, from first to last and return them as a list.
   * The sorting is performed by finding the last timestamp (as specified in
   * {@link ContainerTimestampUtils#findLastTimestamp(Collection)}), adding it at the beginning of the sorted list, and
   * then repeating the same process until all the unsorted timestamps are processed.
   * If, at any point, it is not possible to determine the last timestamp, then all the unprocessed timestamps are added
   * at the beginning of the sorted list in the order they were added into this processor.
   * The contents of available manifests must be successfully parsable for this method to succeed.
   *
   * @return list of timestamp sorted from first to last
   *
   * @see #addTimestamp(CadesTimestamp)
   * @see #addManifest(AsicArchiveManifest, Function)
   * @see ContainerTimestampUtils#findLastTimestamp(Collection)
   */
  public List<ContainerTimestampWrapper> getTimestampsInSortedOrder() {
    List<ContainerTimestampWrapper> orderedTimestamps = new ArrayList<>(timestampMappings.size());

    if (timestampMappings.size() <= 1) {
      if (!timestampMappings.isEmpty()) {
        orderedTimestamps.addAll(timestampMappings.values());
      }
      return orderedTimestamps;
    }

    Set<ContainerTimestampWrapper> unprocessedTimestamps = new LinkedHashSet<>(timestampMappings.values());
    Deque<ContainerTimestampWrapper> timestampsDeque = new LinkedList<>();

    while (!unprocessedTimestamps.isEmpty()) {
      ContainerTimestampWrapper lastTimestamp = ContainerTimestampUtils.findLastTimestamp(unprocessedTimestamps);
      if (lastTimestamp == null) {
        orderedTimestamps.addAll(unprocessedTimestamps);
        break;
      }
      unprocessedTimestamps.remove(lastTimestamp);
      timestampsDeque.addFirst(lastTimestamp);
    }

    orderedTimestamps.addAll(timestampsDeque);
    return orderedTimestamps;
  }

}
