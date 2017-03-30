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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.EncryptedDataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.BDocCryptoRecipientsFile;
import org.digidoc4j.impl.bdoc.manifest.AsicManifest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.MimeType;

public class AsicContainerCreator {

  private static final Logger logger = LoggerFactory.getLogger(AsicContainerCreator.class);
  private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
  private static final Charset CHARSET = StandardCharsets.UTF_8;
  private ZipOutputStream zipOutputStream;
  private ByteArrayOutputStream outputStream;
  private String zipComment;

  public AsicContainerCreator(File containerPathToSave) {
    logger.debug("Starting to save bdoc zip container to " + containerPathToSave);
    try {
      FileOutputStream outputStream = new FileOutputStream(containerPathToSave);
      zipOutputStream = new ZipOutputStream(new BufferedOutputStream(outputStream), CHARSET);
    } catch (FileNotFoundException e) {
      logger.error("Unable to create BDoc ZIP container: " + e.getMessage());
      throw new TechnicalException("Unable to create BDoc ZIP container", e);
    }
  }

  public AsicContainerCreator() {
    outputStream = new ByteArrayOutputStream();
    zipOutputStream = new ZipOutputStream(new BufferedOutputStream(outputStream), CHARSET);
  }

  public void finalizeZipFile() {
    logger.debug("Finalizing bdoc zip file");
    try {
      zipOutputStream.close();
    } catch (IOException e) {
      logger.error("Unable to finish creating BDoc ZIP container: " + e.getMessage());
      throw new TechnicalException("Unable to finish creating BDoc ZIP container", e);
    }
  }

  public InputStream fetchInputStreamOfFinalizedContainer() {
    logger.debug("Fetching input stream of the finalized container");
    return new ByteArrayInputStream(outputStream.toByteArray());
  }

  public void writeAsiceMimeType() {
    logger.debug("Writing asic mime type to bdoc zip file");
    String mimeTypeString = MimeType.ASICE.getMimeTypeString();
    byte[] mimeTypeBytes = mimeTypeString.getBytes();
    ZipEntry entryMimetype = getAsicMimeTypeZipEntry(mimeTypeBytes);
    writeZipEntry(entryMimetype, mimeTypeBytes);
  }

  public void writeManifest(Collection<DataFile> dataFiles) {
    logger.debug("Writing bdoc manifest");
    AsicManifest manifest = new AsicManifest();
    manifest.addFileEntry(dataFiles);
    byte[] entryBytes = manifest.getBytes();
    writeZipEntry(new ZipEntry(AsicManifest.XML_PATH), entryBytes);
  }

  public void writeDataFiles(Collection<DataFile> dataFiles) {
    logger.debug("Adding data files to the bdoc zip container");
    for (DataFile dataFile : dataFiles) {
      String name = dataFile.getName();
      logger.debug("Adding data file " + name);
      ZipEntry entryDocument = new ZipEntry(name);
      zipOutputStream.setLevel(ZipEntry.DEFLATED);
      byte[] entryBytes = dataFile.getBytes();
      writeZipEntry(entryDocument, entryBytes);
    }
  }

  public void writeEncryptedDataFiles(Collection<EncryptedDataFile> encryptedDataFiles) {
    logger.debug("Adding encrypted data files to the bdoc zip container");
    for (EncryptedDataFile encryptedDataFile : encryptedDataFiles) {
      String name = encryptedDataFile.getName();
      logger.debug("Adding data file " + name);
      ZipEntry entryDocument = new ZipEntry(name);
      zipOutputStream.setLevel(ZipEntry.STORED);
      byte[] entryBytes = encryptedDataFile.getBytes();
      writeZipEntry(entryDocument, entryBytes);
    }
  }

  public void writeSignatures(Collection<Signature> signatures, int nextSignatureFileNameIndex) {
    logger.debug("Adding signatures to the bdoc zip container");
    int index = nextSignatureFileNameIndex;
    for (Signature signature : signatures) {
      String signatureFileName = "META-INF/signatures" + index + ".xml";
      ZipEntry entryDocument = new ZipEntry(signatureFileName);
      byte[] entryBytes = signature.getAdESSignature();
      writeZipEntry(entryDocument, entryBytes);
      index++;
    }
  }

  public void writeExistingEntries(Collection<AsicEntry> asicEntries) {
    logger.debug("Writing existing zip container entries");
    for (AsicEntry asicEntry : asicEntries) {
      DSSDocument content = asicEntry.getContent();
      byte[] entryBytes = getDocumentBytes(content);
      ZipEntry zipEntry = asicEntry.getZipEntry();
      if(!StringUtils.equalsIgnoreCase(ZIP_ENTRY_MIMETYPE, zipEntry.getName())) {
        zipOutputStream.setLevel(ZipEntry.DEFLATED);
      }
      writeZipEntryWithoutComment(zipEntry, entryBytes);
    }
  }

  public void writeContainerComment(String comment) {
    logger.debug("Writing container comment: " + comment);
    zipOutputStream.setComment(comment);
  }

  public void setZipComment(String zipComment) {
    this.zipComment = zipComment;
  }

  private ZipEntry getAsicMimeTypeZipEntry(byte[] mimeTypeBytes) {
    ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
    entryMimetype.setMethod(ZipEntry.STORED);
    entryMimetype.setSize(mimeTypeBytes.length);
    entryMimetype.setCompressedSize(mimeTypeBytes.length);
    CRC32 crc = new CRC32();
    crc.update(mimeTypeBytes);
    entryMimetype.setCrc(crc.getValue());
    return entryMimetype;
  }

  private void writeZipEntry(ZipEntry zipEntry, byte[] entryBytes) {
    zipEntry.setComment(zipComment);
    writeZipEntryWithoutComment(zipEntry, entryBytes);
  }

  private void writeZipEntryWithoutComment(ZipEntry zipEntry, byte[] entryBytes) {
    try {
      zipOutputStream.putNextEntry(zipEntry);
      zipOutputStream.write(entryBytes);
      zipOutputStream.closeEntry();
    } catch (IOException e) {
      logger.error("Unable to write Zip entry to BDoc container: " + e.getMessage());
      throw new TechnicalException("Unable to write Zip entry to BDoc container", e);
    }
  }

  private byte[] getDocumentBytes(DSSDocument content) {
    try {
      return IOUtils.toByteArray(content.openStream());
    } catch (IOException e) {
      logger.error("Error getting document content: " + e.getMessage());
      throw new TechnicalException("Error getting document content: " + e.getMessage(), e);
    }
  }

  public void writeCryptoRecipients(byte[] bDocCryptoRecipientsFileBytes) {
    logger.debug("Writing bdoc crypto recipients file");
    ZipEntry zipEntry = new ZipEntry(BDocCryptoRecipientsFile.XML_PATH);
    writeZipEntry(zipEntry, bDocCryptoRecipientsFileBytes);
  }
}
