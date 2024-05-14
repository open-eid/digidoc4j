/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.DuplicateTimestampException;
import org.digidoc4j.exceptions.IllegalTimestampException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.RemovingTimestampException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.TimestampNotFoundException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.AsicContainerCreator;
import org.digidoc4j.impl.asic.AsicContainerValidator;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicSignatureOpener;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestamp;
import org.digidoc4j.impl.asic.cades.TimestampUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by Andrei on 7.11.2017.
 */
public class AsicSContainer extends AsicContainer {

  private static final Logger log = LoggerFactory.getLogger(AsicSContainer.class);
  private static final String DEFAULT_TIMESTAMP_MANIFEST = ASiCUtils.META_INF_FOLDER +
          ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + ASiCUtils.XML_EXTENSION;

  private final List<AsicSContainerTimestamp> timestamps = new ArrayList<>();

  /**
   * AsicSContainer constructor.
   */
  public AsicSContainer() {
    super();
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param configuration configuration
   */
  public AsicSContainer(Configuration configuration) {
    super(configuration);
    setType(Constant.ASICS_CONTAINER_TYPE);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param containerPath path
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public AsicSContainer(String containerPath) {
    super(containerPath, Constant.ASICS_CONTAINER_TYPE);
    Optional.ofNullable(getContainerParseResult()).ifPresent(this::populateContainerWithParseResult);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param containerPath path
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(String, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromExistingFile(String)} instead.
   */
  @Deprecated
  public AsicSContainer(String containerPath, Configuration configuration) {
    super(containerPath, configuration, Constant.ASICS_CONTAINER_TYPE);
    Optional.ofNullable(getContainerParseResult()).ifPresent(this::populateContainerWithParseResult);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param stream input stream
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public AsicSContainer(InputStream stream) {
    super(stream, Constant.ASICS_CONTAINER_TYPE);
    Optional.ofNullable(getContainerParseResult()).ifPresent(this::populateContainerWithParseResult);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param stream input stream
   * @param configuration configuration
   *
   * @deprecated Deprecated for removal. Use {@link org.digidoc4j.ContainerOpener#open(InputStream, Configuration)} or
   * {@link org.digidoc4j.ContainerBuilder#fromStream(InputStream)} instead.
   */
  @Deprecated
  public AsicSContainer(InputStream stream, Configuration configuration) {
    super(stream, configuration, Constant.ASICS_CONTAINER_TYPE);
    Optional.ofNullable(getContainerParseResult()).ifPresent(this::populateContainerWithParseResult);
  }

  /**
   * AsicSContainer constructor.
   *
   * @param containerParseResult container parsed result
   * @param configuration configuration
   */
  public AsicSContainer(AsicParseResult containerParseResult, Configuration configuration) {
    super(containerParseResult, configuration, Constant.ASICS_CONTAINER_TYPE);
    populateContainerWithParseResult(containerParseResult);
  }

  @Override
  public void addTimestamp(Timestamp timestamp) {
    if (timestamp == null) {
      throw new TechnicalException("Timestamp must not be null");
    } else if (!(timestamp instanceof AsicSContainerTimestamp)) {
      throw new TechnicalException("Timestamp must be an instance of " + AsicSContainerTimestamp.class.getSimpleName());
    } else if (timestamps.contains(timestamp)) {
      throw new DuplicateTimestampException("Container already contains timestamp: " + timestamp.getUniqueId());
    }

    addTimestampToContainer((AsicSContainerTimestamp) timestamp);
  }

  @Override
  public List<Timestamp> getTimestamps() {
    return Collections.unmodifiableList(timestamps);
  }

  @Override
  public void removeTimestamp(Timestamp timestamp) {
    if (timestamp == null) {
      log.warn("Cannot remove null timestamp");
      return;
    }

    if (!timestamps.contains(timestamp)) {
      throw new TimestampNotFoundException("Timestamp not found: " + timestamp.getUniqueId());
    }

    removeTimestampFromContainer((AsicSContainerTimestamp) timestamp);
  }

  @Override
  @Deprecated
  public DataFile getTimeStampToken() {
    if (CollectionUtils.isEmpty(timestamps)) {
      return null;
    } else if (timestamps.size() == 1) {
      DataFile dataFile = new DataFile();
      dataFile.setDocument(timestamps.get(0).getTimestampDocument());
      return dataFile;
    }
    throw new NotSupportedException("Container contains more than 1 timestamp. Use getTimestamps() instead.");
  }

  @Override
  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    if (CollectionUtils.size(timestamps) > 1) {
      throw new NotSupportedException("Container contains more than 1 timestamp. Cannot replace any.");
    }
    AsicSContainerTimestamp timestamp = new AsicSContainerTimestamp(timeStampToken.getDocument());
    if (CollectionUtils.isNotEmpty(timestamps)) {
      removeTimestamp(timestamps.get(0));
    }
    addTimestamp(timestamp);
  }

  @Override
  public void save(OutputStream out) {
    writeAsicContainer(new AsicContainerCreator(out, getConfiguration()));
  }

  @Override
  protected AsicSignatureOpener getSignatureOpener() {
    return new AsicSSignatureOpener(getConfiguration());
  }

  @Override
  protected AsicContainerValidator getContainerValidator(AsicParseResult containerParseResult, boolean dataFilesHaveChanged) {
    if (containerParseResult != null) {
      return new AsicSContainerValidator(containerParseResult, getConfiguration(), !dataFilesHaveChanged);
    } else {
      return new AsicSContainerValidator(getConfiguration());
    }
  }

  /**
   * Replace Data File in AsicS container
   *
   * @param dataFile
   */
  @Deprecated
  public void replaceDataFile(DataFile dataFile){
    if (getDataFiles().size() > 0){
      removeDataFile(getDataFiles().get(0));
    }
    addDataFile(dataFile);
  }

  protected String createUserAgent() {
    return Constant.USER_AGENT_STRING;
  }

  @Override
  public void addSignature(Signature signature) {
    throw new NotSupportedException("Not for ASiC-S container");
  }

  @Override
  protected void writeContainerTimestamps(AsicContainerCreator zipCreator) {
    if (CollectionUtils.isEmpty(timestamps)) {
      return;
    }

    Set<String> parsedEntryNames = Optional
            .ofNullable(getContainerParseResult())
            .map(AsicParseResult::getAsicEntries)
            .filter(CollectionUtils::isNotEmpty)
            .map(entries -> entries.stream()
                    .map(AsicEntry::getName)
                    .filter(StringUtils::isNotBlank)
                    .collect(Collectors.toSet()))
            .orElseGet(Collections::emptySet);

    for (AsicSContainerTimestamp timestamp : timestamps) {
      DSSDocument timestampDocument = timestamp.getTimestampDocument();
      if (!parsedEntryNames.contains(timestampDocument.getName())) {
        zipCreator.writeMetaInfEntry(timestampDocument);
      }

      if (timestamp.getTimestampManifest() == null) {
        continue;
      }

      DSSDocument manifestDocument = timestamp.getTimestampManifest().getManifestDocument();
      if (!parsedEntryNames.contains(manifestDocument.getName())) {
        zipCreator.writeMetaInfEntry(manifestDocument);
      }
    }
  }

  private void populateContainerWithParseResult(AsicParseResult parseResult) {
    if (parseResult.getTimeStampToken() != null) {
      DSSDocument timestampDocument = parseResult.getTimeStampToken().getDocument();
      timestamps.add(new AsicSContainerTimestamp(timestampDocument));
    }
  }

  private void addTimestampToContainer(AsicSContainerTimestamp timestamp) {
    if (timestamp.getTimestampManifest() != null) {
      Set<String> referencedObjects = new HashSet<>(timestamp.getTimestampManifest().getNonNullEntryNames());
      for (DataFile dataFile : getDataFiles()) {
        if (!referencedObjects.remove(dataFile.getName())) {
          throw new IllegalTimestampException("Cannot add timestamp not covering data file: " + dataFile.getName());
        }
      }

      Set<String> timestampsAndManifests = TimestampUtils.getTimestampAndManifestNames(timestamps);
      Collection<String> intersection = CollectionUtils.intersection(referencedObjects, timestampsAndManifests);
      if (referencedObjects.size() > intersection.size() || timestampsAndManifests.size() > intersection.size()) {
        Collection<String> entriesToRemove = CollectionUtils.subtract(timestampsAndManifests, intersection);
        Collection<String> entriesToAdd = CollectionUtils.subtract(referencedObjects, intersection);
        if (entriesToRemove.size() != 1 || entriesToAdd.size() != 1) {
          throw new IllegalTimestampException("Cannot add timestamp not covering the entire contents of a container");
        }
        renameExistingTimestampManifest(entriesToRemove.iterator().next(), entriesToAdd.iterator().next());
      }
    } else if (CollectionUtils.isNotEmpty(timestamps)) {
      throw new IllegalTimestampException("Cannot add timestamp not covering the entire contents of a container");
    }

    timestamps.add(timestamp);
  }

  private void removeTimestampFromContainer(AsicSContainerTimestamp timestamp) {
    if (TimestampUtils.isTimestampCoveredByTimestamp(timestamp, timestamps)) {
      throw new RemovingTimestampException();
    }

    timestamps.remove(timestamp);
    removeTimestampParsedEntries(timestamp);
    Optional
            .ofNullable(TimestampUtils.findLastTimestamp(timestamps))
            .map(AsicContainerTimestamp::getTimestampManifest)
            .map(AsicArchiveManifest::getManifestDocument)
            .ifPresent(md -> renameContainerDocument(md, DEFAULT_TIMESTAMP_MANIFEST));
  }

  private void removeTimestampParsedEntries(AsicSContainerTimestamp timestamp) {
    AsicParseResult containerParseResult = getContainerParseResult();
    if (containerParseResult != null) {
      containerParseResult.removeAsicEntry(timestamp.getTimestampDocument().getName());
      if (timestamp.getTimestampManifest() != null) {
        containerParseResult.removeAsicEntry(timestamp.getTimestampManifest().getManifestDocument().getName());
      }
    }
  }

  private void renameExistingTimestampManifest(String oldManifestName, String newManifestName) {
    if (TimestampUtils.isEntryCoveredByTimestamp(oldManifestName, timestamps)) {
      throw new IllegalTimestampException("Cannot rename a manifest that is covered by a timestamp");
    } else if (!StringUtils.startsWith(newManifestName, ASiCUtils.META_INF_FOLDER)) {
      throw new IllegalTimestampException("Invalid manifest name: " + newManifestName);
    }

    DSSDocument documentToRename = timestamps.stream()
            .map(AsicContainerTimestamp::getTimestampManifest)
            .filter(Objects::nonNull)
            .map(AsicArchiveManifest::getManifestDocument)
            .filter(md -> StringUtils.equals(md.getName(), oldManifestName))
            .findFirst()
            .orElseThrow(() -> new TechnicalException("Manifest not found: " + oldManifestName));

    renameContainerDocument(documentToRename, newManifestName);
  }

  private void renameContainerDocument(DSSDocument dssDocument, String newName) {
    if (StringUtils.equals(dssDocument.getName(), newName)) {
      return;
    }
    AsicParseResult containerParseResult = getContainerParseResult();
    if (containerParseResult != null) {
      containerParseResult.removeAsicEntry(dssDocument.getName());
    }
    dssDocument.setName(newName);
  }

}
