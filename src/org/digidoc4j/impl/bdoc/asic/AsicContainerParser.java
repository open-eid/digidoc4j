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
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.bdoc.manifest.ManifestEntry;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.signature.StreamDocument;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

public class AsicContainerParser {

  private final static Logger logger = LoggerFactory.getLogger(AsicContainerParser.class);
  //Matches META-INF/*signatures*.xml where the last * is a number
  private static final String SIGNATURES_FILE_REGEX = "META-INF/(.*)signatures(\\d*).xml";
  private static final Pattern SIGNATURE_FILE_ENDING_PATTERN = Pattern.compile("(\\d+).xml");
  private static final String MANIFEST = "META-INF/manifest.xml";
  @Deprecated
  private DSSDocument asicContainer;


  private AsicParseResult parseResult = new AsicParseResult();
  private ZipFile zipFile;
  private ZipInputStream zipInputStream;
  private List<DSSDocument> signatures = new ArrayList<>();
  private List<DataFile> dataFiles = new ArrayList<>();
  private List<DSSDocument> detachedContents = new ArrayList<>();
  private Integer currentSignatureFileIndex;
  private String mimeType;
  private String zipFileComment;
  private List<AsicEntry> asicEntries = new ArrayList<>();
  private Map<String, ManifestEntry> manifestFileItems = Collections.emptyMap();
  private ManifestParser manifestParser;

  public AsicContainerParser(String containerPath) {
    try {
      zipFile = new ZipFile(containerPath);
    } catch (IOException e) {
      logger.error("Error reading container from " + containerPath + " - " + e.getMessage());
      throw new RuntimeException("Error reading container from " + containerPath);
    }
  }

  public AsicContainerParser(InputStream inputStream) {
    zipInputStream = new ZipInputStream(inputStream);
  }

  public AsicParseResult read() {
    if(isZipFile()) {
      parseZipFile();
    } else {
      parseZipStream();
      updateDataFilesMimeType();
    }
    validateParseResult();
    populateParseResult();
    return parseResult;
  }

  private void parseZipFile() {
    logger.debug("Parsing zip file");
    try {
      zipFileComment = zipFile.getComment();
      parseZipFileManifest();
      Enumeration<? extends ZipEntry> entries = zipFile.entries();
      while (entries.hasMoreElements()) {
        ZipEntry zipEntry = entries.nextElement();
        parseEntry(zipEntry);
      }
    } finally {
      IOUtils.closeQuietly(zipFile);
    }
  }

  private void parseZipStream() {
    logger.debug("Parsing zip stream");
    try {
      ZipEntry entry;
      while((entry = zipInputStream.getNextEntry()) != null) {
        parseEntry(entry);
      }
    } catch (IOException e) {
      logger.error("Error reading bdoc container stream: " + e.getMessage());
      throw new TechnicalException("Error reading bdoc container stream: ", e);
    } finally {
      IOUtils.closeQuietly(zipInputStream);
    }
  }

  private void parseZipFileManifest() {
    logger.debug("Parsing manifest");
    ZipEntry entry = zipFile.getEntry(MANIFEST);
    if(entry == null) {
      return;
    }
    parseManifestEntry(entry);
  }

  private void parseManifestEntry(ZipEntry entry) {
    try {
      InputStream manifestStream = getZipEntryInputStream(entry);
      InMemoryDocument manifestFile = new InMemoryDocument(IOUtils.toByteArray(manifestStream));
      manifestParser = new ManifestParser(manifestFile);
      manifestFileItems = manifestParser.getManifestFileItems();
    } catch (IOException e) {
      logger.error("Error parsing manifest file: " + e.getMessage());
      throw new TechnicalException("Error parsing manifest file", e);
    }
  }

  private void parseEntry(ZipEntry entry) {
    String entryName = entry.getName();
    logger.debug("Paring zip entry " + entryName + " with comment: " + entry.getComment());
    if(isMimeType(entryName)) {
      extractMimeType(entry);
    } else if(isManifest(entryName)) {
      if(!isZipFile()) {
        parseManifestEntry(entry);
      }
    } else if(isSignaturesFile(entryName)) {
      determineCurrentSignatureFileIndex(entryName);
      extractSignature(entry);
    } else if(isDataFile(entryName)) {
      extractDataFile(entry);
    } else {
      extractAsicEntry(entry);
    }
  }

  private void extractMimeType(ZipEntry entry) {
    try {
      InputStream zipFileInputStream = getZipEntryInputStream(entry);
      DSSDocument document = new InMemoryDocument(zipFileInputStream);
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
    DSSDocument document = extractStreamDocument(entry);
    DataFile dataFile = new AsicDataFile(document);
    dataFiles.add(dataFile);
    detachedContents.add(document);
    extractAsicEntry(entry, document);
  }

  private DSSDocument extractStreamDocument(ZipEntry entry) {
    InputStream zipFileInputStream = getZipEntryInputStream(entry);
    String fileName = entry.getName();
    String mimeType = getDataFileMimeType(fileName);
    MimeType mimeTypeCode = MimeType.fromMimeTypeString(mimeType);
    return new StreamDocument(zipFileInputStream, fileName, mimeTypeCode);
  }

  private void extractAsicEntry(ZipEntry entry) {
    logger.debug("Extracting asic entry");
    DSSDocument document = extractStreamDocument(entry);
    extractAsicEntry(entry, document);
  }

  private AsicEntry extractAsicEntry(ZipEntry zipEntry, DSSDocument document) {
    AsicEntry asicEntry = new AsicEntry();
    asicEntry.setZipEntry(zipEntry);
    asicEntry.setContent(document);
    asicEntries.add(asicEntry);
    return asicEntry;
  }

  private void extractSignatureAsicEntry(ZipEntry entry, DSSDocument document) {
    AsicEntry asicEntry = extractAsicEntry(entry, document);
    asicEntry.setSignature(true);
  }

  private String getDataFileMimeType(String fileName) {
    if(manifestFileItems.containsKey(fileName)) {
      ManifestEntry manifestEntry = manifestFileItems.get(fileName);
      return manifestEntry.getMimeType();
    } else {
      MimeType mimeType = MimeType.fromFileName(fileName);
      return mimeType.getMimeTypeString();
    }
  }

  private void updateDataFilesMimeType() {
    for(DataFile dataFile: dataFiles) {
      String fileName = dataFile.getName();
      String mimeType = getDataFileMimeType(fileName);
      dataFile.setMediaType(mimeType);
    }
  }

  private void validateParseResult() {
    if(!StringUtils.equalsIgnoreCase(MimeType.ASICE.getMimeTypeString(), mimeType)) {
      logger.error("Container mime type is not " + MimeType.ASICE.getMimeTypeString() + " but is " + mimeType);
      throw new UnsupportedFormatException("Container mime type is not " + MimeType.ASICE.getMimeTypeString() + " but is " + mimeType);
    }
  }

  private void populateParseResult() {
    parseResult.setDataFiles(dataFiles);
    parseResult.setSignatures(signatures);
    parseResult.setCurrentUsedSignatureFileIndex(currentSignatureFileIndex);
    parseResult.setDetachedContents(detachedContents);
    parseResult.setManifestParser(manifestParser);
    parseResult.setZipFileComment(zipFileComment);
    parseResult.setAsicEntries(asicEntries);
  }

  @Deprecated
  public AsicContainerParser(DSSDocument asicContainer) {
    this.asicContainer = asicContainer;
  }

  @Deprecated
  public Integer findCurrentSignatureFileIndex() throws InvalidAsicContainerException {
    logger.debug("Finding the current signature file index of the container");
    try {
      ZipInputStream docStream = new ZipInputStream(asicContainer.openStream());
      ZipEntry entry = docStream.getNextEntry();
      while (entry != null) {
        determineCurrentSignatureFileIndex(entry.getName());
        entry = docStream.getNextEntry();
      }
      logger.debug("The current signature file index is " + currentSignatureFileIndex);
    } catch (IOException e) {
      logger.error("Invalid asic container: " + e.getMessage());
      throw new InvalidAsicContainerException(e);
    }
    return currentSignatureFileIndex;
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
    if(fileEndingFound) {
      String fileEnding = fileEndingMatcher.group();
      String indexNumber = fileEnding.replace(".xml", "");
      int fileIndex = Integer.parseInt(indexNumber);
      if(currentSignatureFileIndex == null || currentSignatureFileIndex <= fileIndex) {
        currentSignatureFileIndex = fileIndex;
      }
    }
  }

  private InputStream getZipEntryInputStream(ZipEntry entry) {
    try {
      if(isZipFile()) {
        return zipFile.getInputStream(entry);
      } else {
        return zipInputStream;
      }
    } catch (IOException e) {
      logger.error("Error reading data file '" + entry.getName() + "' from the bdoc container: " + e.getMessage());
      throw new TechnicalException("Error reading data file '" + entry.getName() + "' from the bdoc container", e);
    }
  }

  private boolean isZipFile() {
    return zipFile != null;
  }

  public static class InvalidAsicContainerException extends RuntimeException {

    public InvalidAsicContainerException(Exception e) {
      super(e);
    }
  }
}
