package org.digidoc4j.utils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Paths;

import static java.nio.file.Files.deleteIfExists;

/**
 *
 */
public final class Helper {

  private static final int ZIP_VERIFICATION_CODE = 0x504b0304;
  private static final int INT_LENGTH = 4;

  private Helper() {
  }

  /**
   * @param stream aa
   * @return aa
   * @throws IOException aa
   */
  public static boolean isZipFile(InputStream stream) throws IOException {
    DataInputStream in = new DataInputStream(stream);

    if (stream.markSupported())
      stream.mark(INT_LENGTH);

    int test = in.readInt();

    if (stream.markSupported())
      stream.reset();

    final int zipVerificationCode = ZIP_VERIFICATION_CODE;
    return test == zipVerificationCode;
  }

  /**
   *
   * @param file aa
   * @return aa
   * @throws IOException aa
   */
  public static boolean isZipFile(File file) throws IOException {
      try(FileInputStream stream = new FileInputStream(file)) {
          return isZipFile(stream);
      }
  }

  /**
   *
   * @param file aa
   * @return aa
   * @throws ParserConfigurationException aa
   */
  public static boolean isXMLFile(File file) throws ParserConfigurationException {
    DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    try {
      builder.parse(file);
    } catch (Exception e) {
      return false;
    }
    return true;
  }

  /**
   *
   * @param file aa
   * @throws IOException aa
   */
  public static void deleteFile(String file) throws IOException {
    deleteIfExists(Paths.get(file));
  }
}
