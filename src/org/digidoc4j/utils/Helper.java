/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.utils;

import static eu.europa.esig.dss.SignatureLevel.ASiC_E_BASELINE_B;
import static eu.europa.esig.dss.SignatureLevel.ASiC_E_BASELINE_LT;
import static eu.europa.esig.dss.SignatureLevel.ASiC_E_BASELINE_LTA;
import static java.nio.file.Files.deleteIfExists;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.Version;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;

public final class Helper {
  private static final Logger logger = LoggerFactory.getLogger(Helper.class);

  private static final int ZIP_VERIFICATION_CODE = 0x504b0304;
  private static final int INT_LENGTH = 4;
  private static final String BDOC_TM_SIGNATURE_LEVEL = "ASiC_E_BASELINE_LT_TM";
  private static final String EMPTY_CONTAINER_SIGNATURE_LEVEL = "ASiC_E";
  public static final String SPECIAL_CHARACTERS = "[\\\\<>:\"/|?*]";

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
   * @param file file to be deleted
   * @throws IOException if an IO Exception occurs
   */
  public static void deleteFile(String file) throws IOException {
    deleteIfExists(Paths.get(file));
  }

  /**
   * Get the signature from a file.
   *
   * @param file  file containing the container
   * @param index index of the signature file
   * @return signature
   * @throws IOException when the signature is not found
   */
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
   * Serialize object.
   *
   * @param object object to be serialized
   * @param filename  name of file to store serialized object in
   */
  public static <T> void serialize(T object, String filename) {
    FileOutputStream fileOut = null;
    ObjectOutputStream out = null;
    try {
      fileOut = new FileOutputStream(filename);
      out = new ObjectOutputStream(fileOut);
      out.writeObject(object);
      out.flush();
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(out);
      IOUtils.closeQuietly(fileOut);
    }

  }

  /**
   * Deserialize a previously serialized container
   *
   * @param filename name of the file containing the serialized container
   * @return container
   */
  public static <T> T deserializer(String filename) {
    FileInputStream fileIn = null;
    ObjectInputStream in = null;
    try {
      fileIn = new FileInputStream(filename);
      in = new ObjectInputStream(fileIn);
      T object = (T) in.readObject();
      return object;
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(in);
      IOUtils.closeQuietly(fileIn);
    }
  }

  /**
   * Creates a buffered output stream for a given file.
   * @param file target file.
   * @return stream
   */
  public static OutputStream bufferedOutputStream(File file) {
    try {
      return new BufferedOutputStream(new FileOutputStream(file));
    } catch (FileNotFoundException e) {
      throw new DigiDoc4JException(e);
    }
  }

  /** creates user agent value for given container
   * format is:
   *    LIB DigiDoc4J/VERSION format: CONTAINER_TYPE signatureProfile: SIGNATURE_PROFILE
   *    Java: JAVA_VERSION/JAVA_PROVIDER OS: OPERATING_SYSTEM JVM: JVM
   *
   * @param container  container used for creation user agent
   * @return user agent string
   */
  public static String createUserAgent(Container container) {
    String documentType = container.getDocumentType().toString();
    String version = container.getVersion();
    String signatureProfile = container.getSignatureProfile();
    return createUserAgent(documentType, version, signatureProfile);
  }

  public static String createUserAgent(String documentType, String version, String signatureProfile) {
    StringBuilder ua = new StringBuilder("LIB DigiDoc4j/").append(Version.VERSION == null ? "DEV" : Version.VERSION);

    ua.append(" format: ").append(documentType);
    if (version != null) {
      ua.append("/").append(version);
    }

    if(signatureProfile != null) {
      ua.append(" signatureProfile: ").append(signatureProfile);
    }

    ua.append(" Java: ").append(System.getProperty("java.version"));
    ua.append("/").append(System.getProperty("java.vendor"));

    ua.append(" OS: ").append(System.getProperty("os.name"));
    ua.append("/").append(System.getProperty("os.arch"));
    ua.append("/").append(System.getProperty("os.version"));

    ua.append(" JVM: ").append(System.getProperty("java.vm.name"));
    ua.append("/").append(System.getProperty("java.vm.vendor"));
    ua.append("/").append(System.getProperty("java.vm.version"));

    String userAgent = ua.toString();
    logger.debug("User-Agent: " + userAgent);

    return userAgent;
  }

  public static String createBDocUserAgent() {
    return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, EMPTY_CONTAINER_SIGNATURE_LEVEL);
  }

  public static String createBDocUserAgent(SignatureProfile signatureProfile) {
    if(signatureProfile == SignatureProfile.LT_TM) {
      return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, BDOC_TM_SIGNATURE_LEVEL);
    }
    SignatureLevel signatureLevel = determineSignatureLevel(signatureProfile);
    return createBDocUserAgent(signatureLevel);
  }

  private static String createBDocUserAgent(SignatureLevel signatureLevel) {
    return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, signatureLevel.name());
  }

  private static SignatureLevel determineSignatureLevel(SignatureProfile signatureProfile) {
    if(signatureProfile == SignatureProfile.B_BES) {
      return ASiC_E_BASELINE_B;
    } else if(signatureProfile == SignatureProfile.LTA) {
      return ASiC_E_BASELINE_LTA;
    } else {
      return ASiC_E_BASELINE_LT;
    }
  }

  /**
   * Checks that file name contains special characters
   *
   * @param fileName
   * @return true if file name contains following symbols: <>:"/\|?*
   */
  public static boolean hasSpecialCharacters(String fileName) {
    Pattern special = Pattern.compile(SPECIAL_CHARACTERS);
    Matcher hasSpecial = special.matcher(fileName);
    return hasSpecial.find();
  }
}
