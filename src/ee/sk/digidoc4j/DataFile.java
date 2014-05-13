package ee.sk.digidoc4j;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;

/**
 * Data file wrapper providing methods for handling signed files or files to be signed in Container
 */
public class DataFile {
  /**
   * Calculates digest http://www.w3.org/2001/04/xmlenc#sha256 for the data file. If the digest has already been calculated it will return it, otherwise it calculates the digest

   * <p>In case of DDoc http://www.w3.org/2000/09/xmldsig#sha1 is used</p>
   *
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public byte[] calculateDigest() throws Exception {
    return null;
  }

  /**
   * Calculates digest for data file. If digest is already calculated returns it, otherwise calculates the digest.
   * <p>Supported uris for BDoc:</p>
   * <br></br>http://www.w3.org/2000/09/xmldsig#sha1
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha224
   * <br>http://www.w3.org/2001/04/xmlenc#sha256
   * <br>http://www.w3.org/2001/04/xmldsig-more#sha384
   * <br>http://www.w3.org/2001/04/xmlenc#sha512
   * <p>In case of DDoc files the parameter is ignored and SHA1 hash is always returned</p>
   *
   * @param method method uri for calculating the digest
   * @return calculated digest
   * @throws Exception thrown if the file does not exist or the digest calculation fails.
   */
  public byte[] calculateDigest(URL method) throws Exception {
    return null;
  }

  /**
   * Returns the data file name
   */
  public String getFileName() {
    return null;
  }

  /**
   * Returns the data file size
   */
  public Long getFileSize() {
    return null;
  }

  /**
   * Returns the data file getFileId
   */
  public String getFileId() {
    return null;
  }

  /**
   * Returns the data file's media type
   */
  public String getMediaType() {
    return null;
  }

  /**
   * Saves a copy of the data file as file specified by the stream
   *
   * @param out stream where data is written
   * @throws java.io.IOException
   */
  public void saveAs(OutputStream out) throws IOException{
  }

  /**
   * Saves a copy of the data file as file specified by the path
   *
   * @param path full file path where the data file should be saved to. If the file exists it will be overwritten
   * @throws java.io.IOException thrown if part of the path does not exist or the path is an existing directory (without file name)
   */
  public void saveAs(String path) throws IOException {
  }


}
