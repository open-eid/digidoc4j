/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.main;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.MimeType;

/**
 * Container executor for batch task e.g. input folder and output folder
 */
public class MultipleContainersExecutor {

  private final Logger log = LoggerFactory.getLogger(MultipleContainersExecutor.class);
  private final CommandLineExecutor commandLineExecutor;
  private Container.DocumentType containerType;
  private File inputDir;
  private File outputDir;

  /**
   * @param commandLine command line
   */
  public MultipleContainersExecutor(CommandLine commandLine) {
    this.commandLineExecutor = new CommandLineExecutor(ExecutionContext.of(commandLine));
  }

  /**
   * Processing all the files from input folder
   */
  public void execute() {
    this.inputDir = this.getInputDirectory();
    this.outputDir = this.getOutputDirectory();
    this.containerType = this.commandLineExecutor.getContainerType();
    File[] documents = this.inputDir.listFiles();
    for (File document : documents) {
      if (!document.isDirectory()) {
        this.signDocument(document);
      } else {
        this.log.debug("Skipping directory " + document.getName());
      }
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void signDocument(File document) {
    String documentPath = document.getPath();
    String mimeType = this.getMimeType(documentPath);
    Container container = ContainerBuilder.aContainer(this.containerType.name()).withDataFile(documentPath, mimeType).
        build();
    this.commandLineExecutor.processContainer(container);
    this.commandLineExecutor.saveContainer(container, this.createContainerPathToSave(document));
  }

  private String createContainerPathToSave(File document) {
    String extension = this.containerType.name().toLowerCase();
    String containerName = FilenameUtils.removeExtension(document.getName()) + "." + extension;
    String pathToSave = new File(this.outputDir, containerName).getPath();
    if (new File(pathToSave).exists()) {
      throw new DigiDoc4JUtilityException(7,
          String.format("Failed to save container to <%s>, file already exists", pathToSave));
    }
    return pathToSave;
  }

  private File getInputDirectory() {
    return this.getDirectory(this.commandLineExecutor.getContext().getCommandLine().getOptionValue("inputDir"));
  }

  private File getOutputDirectory() {
    File folder = this.getDirectory(this.commandLineExecutor.getContext().getCommandLine().getOptionValue("outputDir"));
    if (!folder.exists()) {
      try {
        Files.createDirectory(folder.toPath());
      } catch (IOException e) {
        throw new DigiDoc4JUtilityException(8, String.format("Unable to create output folder to <%s>", folder));
      }
    }
    return folder;
  }

  private File getDirectory(String outputDirPath) {
    File folder = new File(outputDirPath);
    if (folder.exists() && !folder.isDirectory()) {
      throw new DigiDoc4JUtilityException(6, String.format("Path <%s> is not a directory", outputDirPath));
    }
    return folder;
  }

  private String getMimeType(String documentPath) {
    String mimeType = this.commandLineExecutor.getContext().getCommandLine().getOptionValue("mimeType");
    if (StringUtils.isNotBlank(mimeType)) {
      return mimeType;
    }
    return MimeType.fromFileName(documentPath).getMimeTypeString();
  }

}
