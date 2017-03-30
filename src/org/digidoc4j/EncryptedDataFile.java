package org.digidoc4j;

import java.io.InputStream;

/**
 * Created by Kaarel Raspel on 24/03/17.
 */
public class EncryptedDataFile extends DataFile {

  public EncryptedDataFile(String path, String mimeType) {
    super(path, mimeType);
  }

  public EncryptedDataFile(byte[] data, String fileName, String mimeType) {
    super(data, fileName, mimeType);
  }

  public EncryptedDataFile(InputStream stream, String fileName, String mimeType) {
    super(stream, fileName, mimeType);
  }

}
