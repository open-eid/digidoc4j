/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.util;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class TestZipUtil {

  @SafeVarargs
  public static byte[] writeEntriesToByteArray(Pair<ZipEntry, byte[]>... entries) {
    return writeEntriesToByteArray(Arrays.asList(entries));
  }

  public static byte[] writeEntriesToByteArray(List<Pair<ZipEntry, byte[]>> entries) {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream)) {
      writeEntries(zipOutputStream, entries);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write ZIP container to byte array", e);
    }
    return byteArrayOutputStream.toByteArray();
  }

  @SafeVarargs
  public static void writeEntriesToFile(File file, Pair<ZipEntry, byte[]>... entries) {
    writeEntriesToFile(file, Arrays.asList(entries));
  }

  public static void writeEntriesToFile(File file, List<Pair<ZipEntry, byte[]>> entries) {
    writeEntriesToFile(file.toPath(), entries);
  }

  @SafeVarargs
  public static void writeEntriesToFile(Path path, Pair<ZipEntry, byte[]>... entries) {
    writeEntriesToFile(path, Arrays.asList(entries));
  }

  public static void writeEntriesToFile(Path path, List<Pair<ZipEntry, byte[]>> entries) {
    try (
            OutputStream outputStream = Files.newOutputStream(path, StandardOpenOption.WRITE);
            ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream);
    ) {
      writeEntries(zipOutputStream, entries);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write ZIP file: " + path, e);
    }
  }

  @SafeVarargs
  public static void writeEntries(ZipOutputStream zipOutputStream, Pair<ZipEntry, byte[]>... entries) {
    writeEntries(zipOutputStream, Arrays.asList(entries));
  }

  public static void writeEntries(ZipOutputStream zipOutputStream, List<Pair<ZipEntry, byte[]>> entries) {
    for (Pair<ZipEntry, byte[]> entry : entries) {
      ZipEntry zipEntry = entry.getKey();
      try {
        zipOutputStream.putNextEntry(zipEntry);
        zipOutputStream.write(entry.getValue());
        zipOutputStream.closeEntry();
      } catch (IOException e) {
        throw new IllegalStateException("Failed to write ZIP entry: " + zipEntry.getName(), e);
      }
    }
  }

  public static Pair<ZipEntry, byte[]> createDeflatedEntry(String entryName, byte[] entryContent) {
    return new ImmutablePair<>(createDeflatedZipEntry(entryName, entryContent), entryContent);
  }

  public static ZipEntry createDeflatedZipEntry(String entryName, byte[] entryContent) {
    ZipEntry zipEntry = new ZipEntry(entryName);
    zipEntry.setMethod(ZipEntry.DEFLATED);

    return zipEntry;
  }

  public static Pair<ZipEntry, byte[]> createStoredEntry(String entryName, byte[] entryContent) {
    return new ImmutablePair<>(createStoredZipEntry(entryName, entryContent), entryContent);
  }

  public static ZipEntry createStoredZipEntry(String entryName, byte[] entryContent) {
    ZipEntry zipEntry = new ZipEntry(entryName);
    zipEntry.setMethod(ZipEntry.STORED);

    zipEntry.setCrc(calculateCrc32(entryContent));
    zipEntry.setCompressedSize(entryContent.length);
    zipEntry.setSize(entryContent.length);

    return zipEntry;
  }

  public static long calculateCrc32(byte[] content) {
    CRC32 crc32 = new CRC32();
    crc32.update(content);
    return crc32.getValue();
  }

  private TestZipUtil() {
  }

}
