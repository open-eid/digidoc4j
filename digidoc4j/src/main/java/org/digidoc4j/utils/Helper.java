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

import static java.lang.Math.min;
import static java.nio.file.Files.deleteIfExists;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import javax.swing.filechooser.FileNameExtensionFilter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.CanReadFileFilter;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.Version;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.xades.validation.XadesSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * Class of helper methods.
 */
public final class Helper {

  public static final String SPECIAL_CHARACTERS = "[\\\\<>:\"/|?*]";
  private static final Logger logger = LoggerFactory.getLogger(Helper.class);
  private static final int ZIP_VERIFICATION_CODE = 0x504b0304;
  private static final int INT_LENGTH = 4;
  private static final String ASIC_E_TM_SIGNATURE_LEVEL = "ASiC_E_BASELINE_LT_TM";
  private static final String ASIC_S_TM_SIGNATURE_LEVEL = "ASiC_S_BASELINE_LT_TM";
  private static final String EMPTY_CONTAINER_SIGNATURE_LEVEL_ASIC_E = "ASiC_E";
  private static final String EMPTY_CONTAINER_SIGNATURE_LEVEL_ASIC_S = "ASiC_S";
  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
  private static Random random = new SecureRandom();

  private Helper() {
  }

  /**
   * @param path folder path
   * @return list of files
   */
  public static File[] getFilesFromPath(Path path) {
    return Helper.getFilesFromPath(path, CanReadFileFilter.CAN_READ);
  }

  /**
   * @param path   folder path
   * @param filter file filter
   * @return list of files
   */
  public static File[] getFilesFromPath(Path path, FileFilter filter) {
    File folder = path.toFile();
    if (folder.isDirectory()) {
      return folder.listFiles(filter);
    } else {
      try {
        return Helper.getFilesFromResourcePath(path, CanReadFileFilter.CAN_READ);
      } catch (IllegalArgumentException e) {
        logger.warn(String.format("Unable to load any file from <%s>", path), e);
      }
    }
    return new File[]{};
  }

  /**
   * @param path resource path
   * @return list of files
   */
  public static File[] getFilesFromResourcePath(Path path) {
    return Helper.getFilesFromResourcePath(path, CanReadFileFilter.CAN_READ);
  }

  /**
   * @param path   resource path
   * @param filter file filter
   * @return list of files
   */
  public static File[] getFilesFromResourcePath(Path path, FileFilter filter) {
    URL url = Helper.class.getClassLoader().getResource(path.toString());
    if (url == null) {
      throw new IllegalArgumentException(String.format("No resource <%s> found", path));
    }
    if ("jar".equals(url.getProtocol())) {
      return Helper.getFilesFromJar(url, filter);
    } else {
      File folder;
      try {
        folder = new File(url.toURI());
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(String.format("Resource path <%s> is malformed", url));
      }
      if (!folder.isDirectory()) {
        throw new IllegalArgumentException(String.format("Resource <%s> is not a folder", path));
      }
      return folder.listFiles(filter);
    }
  }

  /**
   * @param length the length of array
   * @return array of random bytes
   */
  public static byte[] generateRandomBytes(int length) {
    byte[] bytes = new byte[length];
    Helper.random.nextBytes(bytes);
    return bytes;
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
   * Serialize object. NB! Use only for temporal storage. May not be compatible between different product releases
   *
   * @param object object to be serialized
   * @param file   file to store serialized object in
   */
  public static <T> void serialize(T object, File file) {
    FileOutputStream fileOut = null;
    ObjectOutputStream out = null;
    try {
      fileOut = new FileOutputStream(file);
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
   * Serialize object. NB! Use only for temporal storage. May not be compatible between different product releases
   *
   * @param object   object to be serialized
   * @param filename name of file to store serialized object in
   */
  public static <T> void serialize(T object, String filename) {
    Helper.serialize(object, new File(filename));
  }

  /**
   * Deserialize a previously serialized container. NB! Use only for temporal storage. May not be compatible between
   * different product releases
   *
   * @param file file containing the serialized container
   * @return container
   */
  public static <T> T deserializer(File file) {
    FileInputStream fileIn = null;
    ObjectInputStream in = null;
    try {
      fileIn = new FileInputStream(file);
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
   * Deserialize a previously serialized container. NB! Use only for temporal storage. May not be compatible between
   * different product releases
   *
   * @param filename name of the file containing the serialized container
   * @return container
   */
  public static <T> T deserializer(String filename) {
    return Helper.deserializer(new File(filename));
  }

  /**
   * Creates a buffered output stream for a given file.
   *
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

  /**
   * creates user agent value for given container
   * /**
   *
   * @param filePath file location
   * @return X509Certificate
   */
  public static X509Certificate loadCertificate(String filePath) {
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      try (FileInputStream is = new FileInputStream(filePath)) {
        return (X509Certificate) factory.generateCertificate(is);
      }
    } catch (Exception e) {
      throw new RuntimeException(String.format("Unable to load certificate from <%s>", filePath), e);
    }
  }

  /**
   * creates user agent value for given container
   * format is:
   * LIB DigiDoc4J/VERSION format: CONTAINER_TYPE signatureProfile: SIGNATURE_PROFILE
   * Java: JAVA_VERSION/JAVA_PROVIDER OS: OPERATING_SYSTEM JVM: JVM
   *
   * @param container container used for creation user agent
   * @return user agent string
   */
  public static String createUserAgent(Container container) {
    String documentType = container.getDocumentType().toString();
    String version = container.getVersion();
    String signatureProfile = container.getSignatureProfile();
    return Helper.createUserAgent(documentType, version, signatureProfile);
  }

  /**
   * @return user agent
   */
  public static String createUserAgent() {
    return Helper.createUserAgent(null, null, null);
  }

  /**
   * @param documentType     type
   * @param version          version
   * @param signatureProfile signature profile
   * @return user agent
   */
  public static String createUserAgent(String documentType, String version, String signatureProfile) {
    StringBuilder ua = new StringBuilder("LIB DigiDoc4j/").append(Version.VERSION == null ? "DEV" : Version.VERSION);
    if (StringUtils.isNotBlank(documentType)) {
      ua.append(" format: ").append(documentType);
    }
    if (StringUtils.isNotBlank(version)) {
      ua.append("/").append(version);
    }
    if (StringUtils.isNotBlank(signatureProfile)) {
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

  public static String createBDocAsicSUserAgent(SignatureProfile signatureProfile) {
    if (signatureProfile == SignatureProfile.LT_TM) {
      return createUserAgent(MimeType.ASICS.getMimeTypeString(), null, ASIC_S_TM_SIGNATURE_LEVEL);
    }
    SignatureLevel signatureLevel = determineSignatureLevel(signatureProfile);
    return createBDocUserAgent(signatureLevel);
  }

  public static String createBDocAsicSUserAgent() {
    return createUserAgent(MimeType.ASICS.getMimeTypeString(), null, EMPTY_CONTAINER_SIGNATURE_LEVEL_ASIC_S);
  }

  public static String createBDocUserAgent() {
    return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, EMPTY_CONTAINER_SIGNATURE_LEVEL_ASIC_E);
  }

  public static String createBDocUserAgent(SignatureProfile signatureProfile) {
    if (signatureProfile == SignatureProfile.LT_TM) {
      return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, ASIC_E_TM_SIGNATURE_LEVEL);
    }
    SignatureLevel signatureLevel = determineSignatureLevel(signatureProfile);
    return createBDocUserAgent(signatureLevel);
  }

  private static String createBDocUserAgent(SignatureLevel signatureLevel) {
    return createUserAgent(MimeType.ASICE.getMimeTypeString(), null, signatureLevel.name());
  }

  //TODO find solution
  private static SignatureLevel determineSignatureLevel(SignatureProfile signatureProfile) {
    if (signatureProfile == SignatureProfile.B_BES) {
      return SignatureLevel.XAdES_BASELINE_B;
    } else if (signatureProfile == SignatureProfile.LTA) {
      return SignatureLevel.XAdES_BASELINE_LTA;
    } else {
      return SignatureLevel.XAdES_BASELINE_LT;
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

  public static String getIdentifier(String identifier) {
    String id = identifier.trim();
    if (DSSXMLUtils.isOid(id)) {
      id = id.substring(id.lastIndexOf(':') + 1);
    } else {
      return id;
    }
    return id;
  }

  public static SignaturePolicyProvider getBdocSignaturePolicyProvider(DSSDocument signature) {
    SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
    Map<String, DSSDocument> signaturePoliciesById = new HashMap<String, DSSDocument>();
    signaturePoliciesById.put(XadesSignatureValidator.TM_POLICY, signature);

    Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
    signaturePoliciesByUrl.put("https://www.sk.ee/repository/bdoc-spec21.pdf", signature);

    signaturePolicyProvider.setSignaturePoliciesById(signaturePoliciesById);
    signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
    return signaturePolicyProvider;
  }

  /**
   * gets all datafiles as List<byte[]> from Container
   *
   * @param container as Container object
   */
  public static List<byte[]> getAllFilesFromContainerAsBytes(Container container) {
    List<byte[]> files = new ArrayList<>();
    for (DataFile dataFile : container.getDataFiles()) {
      files.add(dataFile.getBytes());
    }
    return files;
  }

  /**
   * gets all datafiles as List<byte[]> from Container path
   *
   * @param pathFrom as String
   */
  public static List<byte[]> getAllFilesFromContainerPathAsBytes(String pathFrom) {
    Container container = ContainerBuilder.
        aContainer().
        fromExistingFile(pathFrom).
        build();

    List<byte[]> files = new ArrayList<>();
    for (DataFile dataFile : container.getDataFiles()) {
      files.add(dataFile.getBytes());
    }
    return files;
  }

  /**
   * Saves all datafiles to specified folder
   *
   * @param container as Container object
   * @param path      as String
   */
  public static void saveAllFilesFromContainerToFolder(Container container, String path) {
    for (DataFile dataFile : container.getDataFiles()) {
      File file = new File(path + File.separator + dataFile.getName());
      DSSUtils.saveToFile(dataFile.getBytes(), file);
    }
  }

  /**
   * Saves all datafiles to specified folder
   *
   * @param pathFrom as String
   * @param pathTo   as String
   */
  public static void saveAllFilesFromContainerPathToFolder(String pathFrom, String pathTo) {
    Container container = ContainerBuilder.
        aContainer().
        fromExistingFile(pathFrom).
        build();

    for (DataFile dataFile : container.getDataFiles()) {
      File file = new File(pathTo + File.separator + dataFile.getName());
      DSSUtils.saveToFile(dataFile.getBytes(), file);
    }
  }

  /**
   * delete tmp files from temp folder created by StreamDocument
   */
  public static void deleteTmpFiles() {
    File dir = new File(System.getProperty("java.io.tmpdir"));
    FilenameFilter filenameFilter = new FilenameFilter() {
      @Override
      public boolean accept(File dir, String name) {
        return name.toLowerCase().startsWith("digidoc4j") && name.toLowerCase().endsWith(".tmp");
      }
    };
    for (File f : dir.listFiles(filenameFilter)) {
      if (!f.delete()) {
        f.deleteOnExit();
        System.gc();
      }
    }
  }

  /**
   * Checks that it's AsicE container
   *
   * @param path
   * @return true if AsicE container
   */
  public static boolean isAsicEContainer(String path) {
    String extension = FilenameUtils.getExtension(path);
    if ("sce".equals(extension) || "asice".equals(extension)) {
      return true;
    } else if ("zip".equals(extension)) {
      try {
        return parseAsicContainer(new BufferedInputStream(new FileInputStream(path)), MimeType.ASICE);
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return false;
  }

  /**
   * Checks that it's AsicS container
   *
   * @param stream
   * @return true if AsicS container
   */
  public static boolean isAsicEContainer(BufferedInputStream stream) {
    boolean isAsic = false;
    try {
      isAsic = parseAsicContainer(stream, MimeType.ASICE);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return isAsic;
  }

  /**
   * Checks that it's AsicS container
   *
   * @param path
   * @return true if AsicS container
   */
  public static boolean isAsicSContainer(String path) {
    String extension = FilenameUtils.getExtension(path);
    if ("scs".equals(extension) || "asics".equals(extension)) {
      return true;
    } else if ("zip".equals(extension)) {
      try {
        return parseAsicContainer(new BufferedInputStream(new FileInputStream(path)), MimeType.ASICS);
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return false;
  }

  /**
   * Checks that it's AsicS container
   *
   * @param stream
   * @return true if AsicS container
   */
  public static boolean isAsicSContainer(BufferedInputStream stream) {
    boolean isAsic = false;
    try {
      isAsic = parseAsicContainer(stream, MimeType.ASICS);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return isAsic;
  }

  private static boolean parseAsicContainer(BufferedInputStream stream, MimeType mtype) throws IOException {
    stream.mark(stream.available() + 1);
    ZipInputStream zipInputStream = new ZipInputStream(stream);
    try {
      ZipEntry entry;
      while ((entry = zipInputStream.getNextEntry()) != null) {
        if (StringUtils.equalsIgnoreCase("mimetype", entry.getName())) {
          InputStream zipFileInputStream = zipInputStream;
          BOMInputStream bomInputStream = new BOMInputStream(zipFileInputStream);
          DSSDocument document = new InMemoryDocument(bomInputStream);
          String mimeType = StringUtils.trim(IOUtils.toString(IOUtils.toByteArray(document.openStream()), "UTF-8"));
          if (StringUtils.equalsIgnoreCase(mimeType, mtype.getMimeTypeString())) {
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.error("Error reading asic container stream: " + e.getMessage());
      throw new TechnicalException("Error reading asic container stream: ", e);
    } finally {
      stream.reset();
    }
    return false;
  }

  /**
   * Checks that it's pades container
   *
   * @param file path
   * @return true in case of pades container
   */
  public static boolean isPdfFile(String file) {
    return FilenameUtils.getExtension(file).equals("pdf");
  }

  /**
   * Method for converting bytes to hex string.
   *
   * @param bytes  Given byte array.
   * @param maxLen Max length of result string.
   * @return String of hex characters.
   */
  public static String bytesToHex(byte[] bytes, int maxLen) {
    char[] hexChars = new char[min(bytes.length, maxLen) * 2];
    for (int j = 0; j < min(bytes.length, maxLen); j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static void printWarningSection(Logger logger, String warningMessage) {
    logger.warn(StringUtils.rightPad("-", warningMessage.length(), "-"));
    logger.warn(warningMessage);
    logger.warn(StringUtils.rightPad("-", warningMessage.length(), "-"));
  }

  public static void printErrorSection(Logger logger, String errorMessage) {
    logger.error(StringUtils.rightPad("-", errorMessage.length(), "-"));
    logger.error(errorMessage);
    logger.error(StringUtils.rightPad("-", errorMessage.length(), "-"));
  }

  /*
   * RESTRICTED METHODS
   */

  private static File[] getFilesFromJar(URL jarUrl, FileFilter filter) {
    try {
      String[] fragments = jarUrl.getPath().split("!", 2);
      if (fragments[1].startsWith("/")) {
        fragments[1] = fragments[1].substring(1);
      }
      File file = new File(new URL(fragments[0]).toURI());
      File outputFolder = Paths.get(System.getProperty("java.io.tmpdir"), file.getName(), fragments[1]).toFile();
      if (!outputFolder.exists()) {
        if (outputFolder.mkdirs()) {
          List<ZipEntry> entries = new ArrayList<>();
          ZipFile zipFile = new ZipFile(file);
          Enumeration<? extends ZipEntry> e = zipFile.entries();
          while (e.hasMoreElements()) {
            ZipEntry entry = e.nextElement();
            if (entry.getName().startsWith(fragments[1]) && !entry.isDirectory()) {
              entries.add(entry);
            }
          }
          for (ZipEntry entry : entries) {
            try (InputStream inputStream = zipFile.getInputStream(entry); OutputStream outputStream = new
                FileOutputStream(Paths.get(outputFolder.getPath(), new File(entry.getName()).getName()).toFile())) {
              IOUtils.copy(inputStream, outputStream);
            }
          }
        } else {
          throw new RuntimeException(String.format("Unable to create output folder <%s>", outputFolder));
        }
      }
      return outputFolder.listFiles(filter);
    } catch (Exception e) {
      logger.error(String.format("Unable to read files from <%s>", jarUrl), e);
    }
    return new File[]{};
  }

  public static class FileExtensionFilter implements FileFilter {

    private final FileNameExtensionFilter filter;

    /**
     * @param extensions extensions
     */
    public FileExtensionFilter(String... extensions) {
      if (ArrayUtils.isEmpty(extensions)) {
        throw new IllegalArgumentException("File extensions can't be unset");
      }
      this.filter = new FileNameExtensionFilter("Missing", extensions);
    }

    @Override
    public boolean accept(File file) {
      return this.filter.accept(file);
    }

  }

}