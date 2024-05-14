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

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * ASIC container creator
 */
public class AsicContainerCreator {

  private static final Logger logger = LoggerFactory.getLogger(AsicContainerCreator.class);

  private static final String ZIP_ENTRY_MIMETYPE = "mimetype";
  private static final Charset CHARSET = StandardCharsets.UTF_8;

  private final ZipOutputStream zipOutputStream;
  private final Configuration configuration;
  private String zipComment;

  /**
   * @param outputStream output stream
   * @param configuration configuration
   */
  public AsicContainerCreator(OutputStream outputStream, Configuration configuration) {
    this.configuration = configuration;
    this.zipOutputStream = new ZipOutputStream(outputStream, CHARSET);
  }

  public void finalizeZipFile() {
    logger.debug("Finalizing asic zip file");
    try {
      zipOutputStream.finish();
    } catch (IOException e) {
      handleIOException("Unable to finish creating asic ZIP container", e);
    } finally {
      Helper.deleteTmpFiles(configuration.getTempFileMaxAge());
    }
  }

  /**
   * @param containerType type
   * @deprecated Deprecated for removal. Use {@link #writeAsicMimeType(String)} instead.
   */
  @Deprecated
  public void writeAsiceMimeType(String containerType) {
    writeAsicMimeType(containerType);
  }

  /**
   * @param containerType type
   */
  public void writeAsicMimeType(String containerType) {
    logger.debug("Writing asic mime type to asic zip file");
    String mimeTypeString;
    if (Constant.ASICS_CONTAINER_TYPE.equals(containerType)){
      mimeTypeString = MimeTypeEnum.ASICS.getMimeTypeString();
    } else {
      mimeTypeString = MimeTypeEnum.ASICE.getMimeTypeString();
    }
    byte[] mimeTypeBytes = mimeTypeString.getBytes(CHARSET);
    new BytesEntryCallback(getAsicMimeTypeZipEntry(mimeTypeBytes), mimeTypeBytes).write();
  }

  /**
   * @param dataFiles list of data files
   * @param containerType type
   */
  public void writeManifest(Collection<DataFile> dataFiles, String containerType) {
    logger.debug("Writing asic manifest");
    final AsicManifest manifest = new AsicManifest(containerType);
    manifest.addFileEntries(dataFiles);
    new EntryCallback(new ZipEntry(AsicManifest.XML_PATH)) {
      @Override
      void doWithEntryStream(OutputStream stream) throws IOException {
        manifest.writeTo(stream);
      }
    }.write();
  }

  /**
   * @param dataFiles list of data files
   */
  public void writeDataFiles(Collection<DataFile> dataFiles) {
    logger.debug("Adding data files to the asic zip container");
    for (DataFile dataFile : dataFiles) {
      String name = dataFile.getName();
      logger.debug("Adding data file {}", name);
      zipOutputStream.setLevel(ZipEntry.DEFLATED);
      new StreamEntryCallback(new ZipEntry(name), dataFile.getStream()).write();
    }
  }

  /**
   * @param signatures list of signatures
   * @param nextSignatureFileNameIndex index
   */
  public void writeSignatures(Collection<Signature> signatures, int nextSignatureFileNameIndex) {
    logger.debug("Adding signatures to the asic zip container");
    int index = nextSignatureFileNameIndex;
    for (Signature signature : signatures) {
      String signatureFileName = "META-INF/signatures" + index + ".xml";
      new BytesEntryCallback(new ZipEntry(signatureFileName), signature.getAdESSignature()).write();
      index++;
    }
  }

  /**
   * @param dataFile data file
   */
  @Deprecated
  public void writeTimestampToken(DataFile dataFile) {
    logger.debug("Adding timestamp token to the asic zip container");
    String timestampFileName = "META-INF/timestamp.tst";
    new StreamEntryCallback(new ZipEntry(timestampFileName), dataFile.getStream()).write();
  }

  /**
   * @param asicEntries list of ASIC entries
   */
  public void writeExistingEntries(Collection<AsicEntry> asicEntries) {
    logger.debug("Writing existing zip container entries");
    asicEntries.stream()
            .sorted(AsicContainerCreator::compareAsicEntriesPrioritizeMimeType)
            .forEach(asicEntry -> {
              DSSDocument content = asicEntry.getContent();
              ZipEntry zipEntry = asicEntry.getZipEntry();
              new StreamEntryCallback(zipEntry, content.openStream(), false).write();
            });
  }

  public void writeMetaInfEntry(DSSDocument metaInfEntry) {
    String entryName = metaInfEntry.getName();
    if (StringUtils.isBlank(entryName)) {
      throw new IllegalArgumentException("Unnamed entry");
    } else if (!StringUtils.startsWith(entryName, ASiCUtils.META_INF_FOLDER)) {
      entryName = ASiCUtils.META_INF_FOLDER + entryName;
    }
    new StreamEntryCallback(new ZipEntry(entryName), metaInfEntry.openStream()).write();
  }

  /**
   * @param comment comment
   */
  public void writeContainerComment(String comment) {
    logger.debug("Writing container comment: {}", comment);
    zipOutputStream.setComment(comment);
  }

  /**
   * @param zipComment comment
   */
  public void setZipComment(String zipComment) {
    this.zipComment = zipComment;
  }

  private class StreamEntryCallback extends EntryCallback {

    private final InputStream inputStream;

    StreamEntryCallback(ZipEntry entry, InputStream inputStream) {
      this(entry, inputStream, true);
    }

    StreamEntryCallback(ZipEntry entry, InputStream inputStream, boolean addComment) {
      super(entry, addComment);
      this.inputStream = inputStream;
    }

    @Override
    void doWithEntryStream(OutputStream stream) throws IOException {
      try (InputStream in = inputStream) {
        IOUtils.copy(in, stream);
      }
    }

  }

  private class BytesEntryCallback extends EntryCallback {

    private final byte[] data;

    BytesEntryCallback(ZipEntry entry, byte[] data) {
      super(entry);
      this.data = data;
    }

    @Override
    void doWithEntryStream(OutputStream stream) throws IOException {
      stream.write(data);
    }

  }

  private abstract class EntryCallback {

    private final ZipEntry entry;
    private final boolean addComment;

    EntryCallback(ZipEntry entry) {
      this(entry, true);
    }

    EntryCallback(ZipEntry entry, boolean addComment) {
      this.entry = entry;
      this.addComment = addComment;
    }

    void write() {
      if (addComment) {
        entry.setComment(zipComment);
      }

      try {
        zipOutputStream.putNextEntry(entry);
        doWithEntryStream(zipOutputStream);
        zipOutputStream.closeEntry();
      } catch (IOException e) {
        handleIOException("Unable to write Zip entry to asic container", e);
      }
    }

    abstract void doWithEntryStream(OutputStream stream) throws IOException;

  }

  private static ZipEntry getAsicMimeTypeZipEntry(byte[] mimeTypeBytes) {
    ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
    entryMimetype.setMethod(ZipEntry.STORED);
    entryMimetype.setSize(mimeTypeBytes.length);
    entryMimetype.setCompressedSize(mimeTypeBytes.length);
    CRC32 crc = new CRC32();
    crc.update(mimeTypeBytes);
    entryMimetype.setCrc(crc.getValue());
    return entryMimetype;
  }

  private static int compareAsicEntriesPrioritizeMimeType(AsicEntry left, AsicEntry right) {
    boolean leftIsMimeType = ZIP_ENTRY_MIMETYPE.equalsIgnoreCase(left.getName());
    boolean rightIsMimeType = ZIP_ENTRY_MIMETYPE.equalsIgnoreCase(right.getName());
    if (leftIsMimeType && !rightIsMimeType) {
      return -1;
    } else if (!leftIsMimeType && rightIsMimeType) {
      return 1;
    } else {
      return 0;
    }
  }

  private static void handleIOException(String message, IOException e) {
    logger.error("{}: {}", message, e.getMessage());
    throw new TechnicalException(message, e);
  }

}
