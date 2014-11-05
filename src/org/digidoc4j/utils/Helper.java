package org.digidoc4j.utils;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Container;
import org.digidoc4j.exceptions.DigiDoc4JException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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
   * @param file aa
   * @return aa
   * @throws IOException aa
   */
  public static boolean isZipFile(File file) throws IOException {
    try (FileInputStream stream = new FileInputStream(file)) {
      return isZipFile(stream);
    }
  }

  /**
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
   * @param file aa
   * @throws IOException aa
   */
  public static void deleteFile(String file) throws IOException {
    deleteIfExists(Paths.get(file));
  }

  public static String extractSignature(String file, int index) throws IOException {
    ZipFile zipFile = new ZipFile(file);
    String signatureFileName = "META-INF/signatures" + index + ".xml";
    ZipEntry entry = zipFile.getEntry(signatureFileName);

    if (entry == null)
      throw new IOException(signatureFileName + " does not exists in archive: " + file);

    InputStream inputStream = zipFile.getInputStream(entry);
    String signatureContent = IOUtils.toString(inputStream, "UTF-8");

    zipFile.close();
    inputStream.close();

    return signatureContent;
  }

  /**
   * Serialize container.
   *
   * @param container container to be serialized
   * @param filename  name of file to store serialized container in
   */
  public static void serialize(Container container, String filename) {

    FileOutputStream fileOut = null;
    try {
      fileOut = new FileOutputStream(filename);
      ObjectOutputStream out = new ObjectOutputStream(fileOut);
      out.writeObject(container);
      out.flush();
      out.close();
      fileOut.close();
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }

  }

  /**
   * Deserialize a previously serialized container
   *
   * @param filename name of the file containing the serialized container
   * @return container
   */
  public static Container deserializer(String filename) {
    FileInputStream fileIn = null;
    try {
      fileIn = new FileInputStream(filename);
      ObjectInputStream in = new ObjectInputStream(fileIn);
      Container container = (Container) in.readObject();
      in.close();
      fileIn.close();

      return container;
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }
  }
}
