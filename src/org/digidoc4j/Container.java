/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.File;
import java.io.InputStream;
import java.io.Serializable;
import java.util.List;

public interface Container extends Serializable {

  DataFile addDataFile(String path, String mimeType);

  DataFile addDataFile(InputStream is, String fileName, String mimeType);

  DataFile addDataFile(File file, String mimeType);

  void addSignature(Signature signature);

  List<DataFile> getDataFiles();

  /**
   * Returns container type "BDOC" or "DDOC"
   */
  String getType();

  List<Signature> getSignatures();

  void removeDataFile(DataFile file);

  void removeSignature(Signature signature);

  void extendSignatureProfile(SignatureProfile profile);

  File saveAsFile(String filePath);

  InputStream saveAsStream();

  ValidationResult validate();
}
