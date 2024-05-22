/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.StreamDocument;
import org.digidoc4j.impl.UncompressedAsicEntry;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;
import org.digidoc4j.impl.asic.cades.ContainerTimestampProcessor;
import org.digidoc4j.impl.asic.cades.ContainerTimestampUtils;
import org.digidoc4j.impl.asic.manifest.ManifestEntry;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;
import org.digidoc4j.utils.MimeTypeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

/**
 * Abstract class for parsing ASiC containers.
 */
public abstract class AsicContainerParser {

  public static final String MANIFEST = "META-INF/manifest.xml";
  public static final String TIMESTAMP_TOKEN = "META-INF/timestamp.tst";

  private static final Logger logger = LoggerFactory.getLogger(AsicContainerParser.class);
  //Matches META-INF/*signatures*.xml where the last * is a number
  private static final String SIGNATURES_FILE_REGEX = "META-INF/(.*)signatures(.*).xml";
  private static final Pattern SIGNATURE_FILE_ENDING_PATTERN = Pattern.compile("(\\d+).xml");

  private final Configuration configuration;
  private final AsicParseResult parseResult = new AsicParseResult();
  private final List<DSSDocument> signatures = new ArrayList<>();
  private final LinkedHashMap<String, DataFile> dataFiles = new LinkedHashMap<>();
  private final ContainerTimestampProcessor timestampProcessor = new ContainerTimestampProcessor();
  private final List<DSSDocument> detachedContents = new ArrayList<>();
  private Integer currentSignatureFileIndex;
  private String mimeType;
  private String zipFileComment;
  private final List<AsicEntry> asicEntries = new ArrayList<>();
  private Map<String, ManifestEntry> manifestFileItems = Collections.emptyMap();
  private ManifestParser manifestParser;
  private final boolean storeDataFilesOnlyInMemory;
  private boolean manifestFound = false;
  private boolean mimeTypeFound = false;
  private final long maxDataFileCachedInBytes;
  private final long zipCompressionRatioCheckThreshold;
  private final long zipMaxAllowedCompressionRatio;

  protected AsicContainerParser(Configuration configuration) {
    this.configuration = configuration;
    storeDataFilesOnlyInMemory = configuration.storeDataFilesOnlyInMemory();
    maxDataFileCachedInBytes = configuration.getMaxDataFileCachedInBytes();
    zipCompressionRatioCheckThreshold = configuration.getZipCompressionRatioCheckThresholdInBytes();
    zipMaxAllowedCompressionRatio = configuration.getMaxAllowedZipCompressionRatio();
  }

  /**
   * Method for parsing and validating ASiC container.
   *
   * @return parsing result
   */
  public AsicParseResult read() {
    parseContainer();
    validateParseResult();
    postProcessTimestamps();
    populateParseResult();
    return parseResult;
  }

  protected abstract void parseContainer();

  protected abstract void extractManifest(ZipEntry entry);

  protected abstract InputStream getZipEntryInputStream(ZipEntry entry);

  protected void parseManifestEntry(DSSDocument manifestFile) {
    logger.debug("Parsing manifest");
    manifestParser = new ManifestParser(manifestFile);
    manifestFileItems = manifestParser.getManifestFileItems();
  }

  protected void parseEntry(ZipEntry entry) {
    String entryName = entry.getName();
    logger.debug("Paring zip entry " + entryName + " with comment: " + entry.getComment());
    if (isMimeType(entryName)) {
      if (this.mimeTypeFound) {
        throw new DigiDoc4JException("Multiple mimetype files disallowed");
      }
      this.mimeTypeFound = true;
      extractMimeType(entry);
    } else if (isManifest(entryName)) {
      if (this.manifestFound) {
        throw new DigiDoc4JException("Multiple manifest.xml files disallowed");
      }
      this.manifestFound = true;
      extractManifest(entry);
    } else if (isSignaturesFile(entryName)) {
      determineCurrentSignatureFileIndex(entryName);
      extractSignature(entry);
    } else if (isDataFile(entryName)) {
      extractDataFile(entry);
    } else if (ContainerTimestampUtils.isTimestampFileName(entryName)) {
      extractTimestamp(entry);
    } else {
      extractAsicEntry(entry);
    }
  }

  private void extractMimeType(ZipEntry entry) {
    try (
            InputStream zipFileInputStream = getZipEntryInputStream(entry);
            BOMInputStream bomInputStream = new BOMInputStream(zipFileInputStream)
    ) {
      InMemoryDocument document = new InMemoryDocument(IOUtils.toByteArray(bomInputStream));
      mimeType = StringUtils.trim(IOUtils.toString(document.getBytes(), "UTF-8"));
      extractUncompressedAsicEntry(entry, document);
    } catch (IOException e) {
      logger.error("Error parsing container mime type: " + e.getMessage());
      throw new TechnicalException("Error parsing container mime type", e);
    }
  }

  private void extractSignature(ZipEntry entry) {
    logger.debug("Extracting signature");
    try (InputStream zipFileInputStream = getZipEntryInputStream(entry)) {
      String fileName = entry.getName();
      InMemoryDocument document = new InMemoryDocument(IOUtils.toByteArray(zipFileInputStream), fileName);
      signatures.add(document);
      extractSignatureAsicEntry(entry, document);
    } catch (IOException e) {
      logger.error("Error parsing container signature: " + e.getMessage());
      throw new TechnicalException("Error parsing container signature", e);
    }
  }

  private void extractTimestamp(ZipEntry entry) {
    logger.debug("Extracting timestamp file");
    DSSDocument timestampDocument = new InMemoryDocument(getZipEntryInputStream(entry), entry.getName(), MimeTypeEnum.TST);
    timestampProcessor.addTimestamp(new CadesTimestamp(timestampDocument));
    extractAsicEntry(entry, timestampDocument);
  }

  private void extractDataFile(ZipEntry entry) {
    logger.debug("Extracting data file");
    String fileName = entry.getName();
    validateDataFile(fileName);
    DSSDocument document = extractStreamDocument(entry);
    DataFile dataFile = new AsicDataFile(document);
    dataFiles.put(fileName, dataFile);
    detachedContents.add(document);
    extractAsicEntry(entry, document);
  }

  private DSSDocument extractStreamDocument(ZipEntry entry) {
    logger.debug("Zip entry size is <{}> bytes", entry.getSize());
    MimeType mimeTypeCode = MimeTypeUtil.mimeTypeOf(this.getDataFileMimeType(entry.getName()));
    if (this.storeDataFilesOnlyInMemory || entry.getSize() <= this.maxDataFileCachedInBytes) {
      return new InMemoryDocument(toByteArray(this.getZipEntryInputStream(entry)), entry.getName(), mimeTypeCode);
    } else {
      return new StreamDocument(this.getZipEntryInputStream(entry), entry.getName(), mimeTypeCode);
    }
  }

  private byte[] toByteArray(InputStream inputStream) {
    try {
      return IOUtils.toByteArray(inputStream);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new TechnicalException(e.getMessage());
    }
  }

  protected AsicEntry extractAsicEntry(ZipEntry entry) {
    logger.debug("Extracting asic entry");
    DSSDocument document = extractStreamDocument(entry);
    return extractAsicEntry(entry, document);
  }

  private AsicEntry extractAsicEntry(ZipEntry zipEntry, DSSDocument document) {
    AsicEntry asicEntry = new AsicEntry(zipEntry);
    asicEntry.setContent(document);
    asicEntries.add(asicEntry);
    return asicEntry;
  }

  private UncompressedAsicEntry extractUncompressedAsicEntry(ZipEntry zipEntry, InMemoryDocument document) {
    UncompressedAsicEntry asicEntry = new UncompressedAsicEntry(zipEntry);
    asicEntry.updateMetadataIfNotPresent(document::getBytes);
    asicEntry.setContent(document);
    asicEntries.add(asicEntry);
    return asicEntry;
  }

  private void extractSignatureAsicEntry(ZipEntry entry, DSSDocument document) {
    AsicEntry asicEntry = extractAsicEntry(entry, document);
    asicEntry.setSignature(true);
  }

  protected String getDataFileMimeType(String fileName) {
    if (manifestFileItems.containsKey(fileName)) {
      ManifestEntry manifestEntry = manifestFileItems.get(fileName);
      return manifestEntry.getMimeType();
    } else {
      MimeType mimetype = MimeType.fromFileName(fileName);
      return mimetype.getMimeTypeString();
    }
  }

  private void validateParseResult() {
    if (!StringUtils.equalsIgnoreCase(MimeTypeEnum.ASICE.getMimeTypeString(), mimeType)
            && !StringUtils.equalsIgnoreCase(MimeTypeEnum.ASICS.getMimeTypeString(), mimeType)) {
      logger.error("Container mime type is not " + MimeTypeEnum.ASICE.getMimeTypeString() + " but is " + mimeType);
      throw new UnsupportedFormatException("Container mime type is not " + MimeTypeEnum.ASICE.getMimeTypeString()
              + " OR " + MimeTypeEnum.ASICS.getMimeTypeString() + " but is " + mimeType);
    }
    if (!this.signatures.isEmpty() && this.dataFiles.isEmpty()) {
      throw new ContainerWithoutFilesException("The reference data object(s) is not found!");
    }
  }

  private void validateDataFile(String fileName) {
    if (dataFiles.containsKey(fileName)) {
      logger.error("Container contains duplicate data file: " + fileName);
      throw new DuplicateDataFileException("Container contains duplicate data file: " + fileName);
    }
  }

  private void postProcessTimestamps() {
    for (AsicEntry asicEntry : asicEntries) {
      if (ContainerTimestampUtils.isArchiveManifestFileName(asicEntry.getName())) {
        AsicArchiveManifest archiveManifest = new AsicArchiveManifest(asicEntry.getContent());
        timestampProcessor.addManifest(archiveManifest, name -> asicEntries.stream()
                .filter(e -> StringUtils.equals(e.getName(), name))
                .map(AsicEntry::getContent)
                .filter(Objects::nonNull)
                .map(CadesTimestamp::new)
                .findFirst()
                .orElse(null));
      }
    }
    try {
      timestampProcessor.resolveReferenceMimeTypes((name, mimeType) -> asicEntries.stream()
              .filter(e -> StringUtils.equals(e.getName(), name))
              .map(AsicEntry::getContent)
              .filter(Objects::nonNull)
              .findFirst()
              .ifPresent(d -> d.setMimeType(mimeType)));
    } catch (Exception e) {
      logger.warn("Failed to resolve mimetypes of timestamped entries");
    }
  }

  private void populateParseResult() {
    Collection<DataFile> files = dataFiles.values();
    parseResult.setDataFiles(new ArrayList<>(files));
    parseResult.setCurrentUsedSignatureFileIndex(currentSignatureFileIndex);
    parseResult.setDetachedContents(detachedContents);
    parseResult.setSignatures(parseSignatures());
    parseResult.setManifestParser(manifestParser);
    parseResult.setZipFileComment(zipFileComment);
    parseResult.setAsicEntries(asicEntries);
    try {
      parseResult.setTimestamps(timestampProcessor.getTimestampsInSortedOrder());
    } catch (Exception e) {
      logger.warn("Failed to determine timestamp token order; using initial container order");
      parseResult.setTimestamps(timestampProcessor.getTimestampsInInitialOrder());
    }
    parseResult.setMimeType(mimeType);
  }

  private List<XadesSignatureWrapper> parseSignatures() {
    AsicSignatureParser signatureParser = new AsicSignatureParser(parseResult.getDetachedContents(), configuration);
    List<XadesSignatureWrapper> parsedSignatures = new ArrayList<>();
    for (DSSDocument signatureDocument : signatures) {
      XadesSignature signature = signatureParser.parse(signatureDocument);
      parsedSignatures.add(new XadesSignatureWrapper(signature, signatureDocument));
    }
    return parsedSignatures;
  }

  private boolean isMimeType(String entryName) {
    return StringUtils.equalsIgnoreCase("mimetype", entryName);
  }

  private boolean isDataFile(String entryName) {
    return !entryName.startsWith("META-INF/") && !isMimeType(entryName);
  }

  private boolean isManifest(String entryName) {
    return StringUtils.equalsIgnoreCase(MANIFEST, entryName);
  }

  private boolean isSignaturesFile(String entryName) {
    return entryName.matches(SIGNATURES_FILE_REGEX);
  }

  private void determineCurrentSignatureFileIndex(String entryName) {
    Matcher fileEndingMatcher = SIGNATURE_FILE_ENDING_PATTERN.matcher(entryName);
    boolean fileEndingFound = fileEndingMatcher.find();
    if (fileEndingFound) {
      String fileEnding = fileEndingMatcher.group();
      String indexNumber = fileEnding.replace(".xml", "");
      int fileIndex = Integer.parseInt(indexNumber);
      if (currentSignatureFileIndex == null || currentSignatureFileIndex <= fileIndex) {
        currentSignatureFileIndex = fileIndex;
      }
    }
  }

  protected void verifyContainerUnpackingIsSafeToProceed(long packedSize, long unpackedSize) {
    if (unpackedSize > zipCompressionRatioCheckThreshold) {
      final long allowedMaximumUnpackedSize = packedSize * zipMaxAllowedCompressionRatio;
      if (unpackedSize > allowedMaximumUnpackedSize) {
        throw new TechnicalException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
      }
    }
  }

  void setZipFileComment(String zipFileComment) {
    this.zipFileComment = zipFileComment;
  }

  LinkedHashMap<String, DataFile> getDataFiles() {
    return dataFiles;
  }
}
