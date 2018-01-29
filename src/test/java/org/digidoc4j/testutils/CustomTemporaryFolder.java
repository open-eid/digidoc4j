package org.digidoc4j.testutils;

import java.io.File;
import java.nio.file.Paths;

import org.junit.rules.TemporaryFolder;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class CustomTemporaryFolder extends TemporaryFolder {

  private File temporaryParentFolder;

  public CustomTemporaryFolder(File parentFolder, String temporaryParentFolderName) {
    super(Paths.get(parentFolder.getPath(), temporaryParentFolderName).toFile());
    this.temporaryParentFolder = Paths.get(parentFolder.getPath(), temporaryParentFolderName).toFile();
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() throws Throwable {
    if (!this.temporaryParentFolder.exists()) {
      this.temporaryParentFolder.mkdir();
    }
    this.create();
  }

}
