package org.digidoc4j;

import java.io.InputStream;

/**
 * Created by Kaarel Raspel on 21/03/17.
 */
public interface OpenableContainer {
  boolean canOpen(InputStream is);
  boolean canOpen(String containerPath);

  FilesContainer open(InputStream is);
  FilesContainer open(String containerPath);

  FilesContainer open(InputStream is, Configuration configuration);
  FilesContainer open(String containerPath, Configuration configuration);
}
