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

import static java.nio.file.Files.deleteIfExists;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.Version;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.bdoc.xades.validation.XadesSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.xades.DSSXMLUtils;

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

  public static String createBDocAsicSUserAgent(SignatureProfile signatureProfile) {
    if(signatureProfile == SignatureProfile.LT_TM) {
      return createUserAgent(MimeType.ASICS.getMimeTypeString(), null, BDOC_TM_SIGNATURE_LEVEL);
    }
    SignatureLevel signatureLevel = determineSignatureLevel(signatureProfile);
    return createBDocUserAgent(signatureLevel);
  }

  public static String createBDocAsicSUserAgent() {
    return createUserAgent(MimeType.ASICS.getMimeTypeString(), null, EMPTY_CONTAINER_SIGNATURE_LEVEL);
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

  //TODO find solution
  private static SignatureLevel determineSignatureLevel(SignatureProfile signatureProfile) {
    if(signatureProfile == SignatureProfile.B_BES) {
      return SignatureLevel.XAdES_BASELINE_B;
    } else if(signatureProfile == SignatureProfile.LTA) {
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

  public static String getIdentifier(String identifier){
    String id = identifier.trim();
    if (DSSXMLUtils.isOid(id)) {
      id = id.substring(id.lastIndexOf(':') + 1);
    } else {
      return id;
    }
    return id;
  }

  public static SignaturePolicyProvider getBdocSignaturePolicyProvider(DSSDocument signature) {
    SignaturePolicyProvider signaturePolicyProvider  = new SignaturePolicyProvider();
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
  public static List<byte[]> getAllFilesFromContainerAsBytes(Container container){
    List<byte[]> files = new ArrayList<>();
    for(DataFile dataFile: container.getDataFiles()){
      files.add(dataFile.getBytes());
    }
    return files;
  }

  /**
   * gets all datafiles as List<byte[]> from Container path
   *
   * @param pathFrom as String
   */
  public static List<byte[]> getAllFilesFromContainerPathAsBytes(String pathFrom){
    Container container = ContainerBuilder.
        aContainer().
        fromExistingFile(pathFrom).
        build();

    List<byte[]> files = new ArrayList<>();
    for(DataFile dataFile: container.getDataFiles()){
      files.add(dataFile.getBytes());
    }
    return files;
  }

  /**
   * Saves all datafiles to specified folder
   *
   * @param container as Container object
   * @param path as String
   */
  public static void saveAllFilesFromContainerToFolder(Container container, String path){
    for(DataFile dataFile: container.getDataFiles()){
      File file = new File(path + File.separator + dataFile.getName());
      DSSUtils.saveToFile(dataFile.getBytes(), file);
    }
  }

  /**
   * Saves all datafiles to specified folder
   *
   * @param pathFrom as String
   * @param pathTo as String
   */
  public static void saveAllFilesFromContainerPathToFolder(String pathFrom, String pathTo){
    Container container = ContainerBuilder.
        aContainer().
        fromExistingFile(pathFrom).
        build();

    for(DataFile dataFile: container.getDataFiles()){
      File file = new File(pathTo + File.separator + dataFile.getName());
      DSSUtils.saveToFile(dataFile.getBytes(), file);
    }
  }

  /**
   * delete tmp files from temp folder created by StreamDocument
   *
   */
  public static void deleteTmpFiles(){
    File dir = new File(System.getProperty("java.io.tmpdir"));
    FilenameFilter filenameFilter = new FilenameFilter() {
      @Override
      public boolean accept(File dir, String name) {
        return name.toLowerCase().startsWith("digidoc4j") && name.toLowerCase().endsWith(".tmp");
      }
    };
    for (File f : dir.listFiles(filenameFilter)) {
      if (!f.delete()){
        f.deleteOnExit();
        System.gc();
      }
    }
  }

  public static boolean isAsicSContainer(String path) {
    String extension = FilenameUtils.getExtension(path);
    if("scs".equals(extension) || "asics".equals(extension)){
      return true;
    }else if("zip".equals(extension)){
      try {
        return parseContainer(new BufferedInputStream(new FileInputStream(path)));
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return false;
  }

  public static boolean isAsicSContainer(BufferedInputStream stream) {
    boolean isAsic = false;
    try {
      isAsic = parseContainer(stream);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return isAsic;
  }

  private static boolean parseContainer(BufferedInputStream stream) throws IOException {
    stream.mark(stream.available()+1);
    ZipInputStream zipInputStream = new ZipInputStream(stream);
    try {
      ZipEntry entry;
      while ((entry = zipInputStream.getNextEntry()) != null) {
        if (StringUtils.equalsIgnoreCase("mimetype", entry.getName())){
          InputStream zipFileInputStream = zipInputStream;
          BOMInputStream bomInputStream = new BOMInputStream(zipFileInputStream);
          DSSDocument document = new InMemoryDocument(bomInputStream);
          String mimeType = StringUtils.trim(IOUtils.toString(IOUtils.toByteArray(document.openStream()), "UTF-8"));
          if (StringUtils.equalsIgnoreCase(mimeType, MimeType.ASICS.getMimeTypeString())){
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.error("Error reading bdoc container stream: " + e.getMessage());
      throw new TechnicalException("Error reading bdoc container stream: ", e);
    } finally {
      stream.reset();
    }
    return false;
  }
}