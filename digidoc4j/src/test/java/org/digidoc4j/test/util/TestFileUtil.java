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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestFileUtil {

  public static FileTime creationTime(Path filePath) {
    try {
      return (FileTime) Files.getAttribute(filePath, "basic:creationTime");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static Signature openAdESSignature(Container container, String file) throws IOException {
    return SignatureBuilder.aSignature(container).openAdESSignature(FileUtils.readFileToByteArray(new File(file)));
  }

}
