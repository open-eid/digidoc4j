/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.asic;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.StreamDocument;
import org.digidoc4j.impl.bdoc.manifest.ManifestEntry;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

public abstract class AsicContainerParser {

  private final static Logger logger = LoggerFactory.getLogger(AsicContainerParser.class);
  //Matches META-INF/*signatures*.xml where the last * is a number
  private static final String SIGNATURES_FILE_REGEX = "META-INF/(.*)signatures(\\d*).xml";
  private static final Pattern SIGNATURE_FILE_ENDING_PATTERN = Pattern.compile("(\\d+).xml");
  public static final String MANIFEST = "META-INF/manifest.xml";
  private AsicParseResult parseResult = new AsicParseResult();
  private List<DSSDocument> signatures = new ArrayList<>();
  private LinkedHashMap<String, DataFile> dataFiles = new LinkedHashMap<>();
  private List<DSSDocument> detachedContents = new ArrayList<>();
  private Integer currentSignatureFileIndex;
  private String mimeType;
  private String zipFileComment;
  private List<AsicEntry> asicEntries = new ArrayList<>();
  private Map<String, ManifestEntry> manifestFileItems = Collections.emptyMap();
  private ManifestParser manifestParser;
  private boolean storeDataFilesOnlyInMemory;
  private long maxDataFileCachedInBytes;

  protected AsicContainerParser(Configuration configuration) {
    storeDataFilesOnlyInMemory = configuration.storeDataFilesOnlyInMemory();
    maxDataFileCachedInBytes = configuration.getMaxDataFileCachedInBytes();
  }

  public AsicParseResult read() {
    parseContainer();
    validateParseResult();
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
      extractMimeType(entry);
    } else if (isManifest(entryName)) {
      extractManifest(entry);
    } else if (isSignaturesFile(entryName)) {
      determineCurrentSignatureFileIndex(entryName);
      extractSignature(entry);
    } else if (isDataFile(entryName)) {
      extractDataFile(entry);
    } else {
      extractAsicEntry(entry);
    }
  }

  private void extractMimeType(ZipEntry entry) {
    try {
      InputStream zipFileInputStream = getZipEntryInputStream(entry);
      BOMInputStream bomInputStream = new BOMInputStream(zipFileInputStream);
      DSSDocument document = new InMemoryDocument(bomInputStream);
      mimeType = StringUtils.trim(IOUtils.toString(document.getBytes(), "UTF-8"));
      extractAsicEntry(entry, document);
    } catch (IOException e) {
      logger.error("Error parsing container mime type: " + e.getMessage());
      throw new TechnicalException("Error parsing container mime type: " + e.getMessage(), e);
    }
  }

  private void extractSignature(ZipEntry entry) {
    logger.debug("Extracting signature");
    InputStream zipFileInputStream = getZipEntryInputStream(entry);
    String fileName = entry.getName();
    InMemoryDocument document = new InMemoryDocument(zipFileInputStream, fileName);
    signatures.add(document);
    extractSignatureAsicEntry(entry, document);
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
    logger.debug("Zip entry size is " + entry.getSize() + " bytes");
    InputStream zipFileInputStream = getZipEntryInputStream(entry);
    String fileName = entry.getName();
    String mimeType = getDataFileMimeType(fileName);
    MimeType mimeTypeCode = MimeType.fromMimeTypeString(mimeType);
    DSSDocument document;
    if(storeDataFilesOnlyInMemory || entry.getSize() <= maxDataFileCachedInBytes) {
      document = new InMemoryDocument(zipFileInputStream, fileName, mimeTypeCode);
    } else {
      document = new StreamDocument(zipFileInputStream, fileName, mimeTypeCode);
    }
    return document;
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

  private void extractSignatureAsicEntry(ZipEntry entry, DSSDocument document) {
    AsicEntry asicEntry = extractAsicEntry(entry, document);
    asicEntry.setSignature(true);
  }

  protected String getDataFileMimeType(String fileName) {
    if (manifestFileItems.containsKey(fileName)) {
      ManifestEntry manifestEntry = manifestFileItems.get(fileName);
      return manifestEntry.getMimeType();
    } else {
      MimeType mimeType = MimeType.fromFileName(fileName);
      return mimeType.getMimeTypeString();
    }
  }

  private void validateParseResult() {
    if (!StringUtils.equalsIgnoreCase(MimeType.ASICE.getMimeTypeString(), mimeType)) {
      logger.error("Container mime type is not " + MimeType.ASICE.getMimeTypeString() + " but is " + mimeType);
      throw new UnsupportedFormatException("Container mime type is not " + MimeType.ASICE.getMimeTypeString() + " but is " + mimeType);
    }
  }

  private void validateDataFile(String fileName) {
    if (dataFiles.containsKey(fileName)) {
      logger.error("Container contains duplicate data file: " + fileName);
      throw new DuplicateDataFileException("Container contains duplicate data file: " + fileName);
    }
  }

  private void populateParseResult() {
    Collection<DataFile> files = dataFiles.values();
    parseResult.setDataFiles(new ArrayList<>(files));
    parseResult.setSignatures(signatures);
    parseResult.setCurrentUsedSignatureFileIndex(currentSignatureFileIndex);
    parseResult.setDetachedContents(detachedContents);
    parseResult.setManifestParser(manifestParser);
    parseResult.setZipFileComment(zipFileComment);
    parseResult.setAsicEntries(asicEntries);
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

  void setZipFileComment(String zipFileComment) {
    this.zipFileComment = zipFileComment;
  }

  LinkedHashMap<String, DataFile> getDataFiles() {
    return dataFiles;
  }
}
