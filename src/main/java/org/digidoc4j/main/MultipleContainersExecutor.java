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

  public void signDocuments() {
    this.inputDir = getInputDirectory();
    this.outputDir = getOutputDirectory();
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
    String extension = containerType.name().toLowerCase();
    String containerName = FilenameUtils.removeExtension(document.getName()) + "." + extension;
    String pathToSave = new File(outputDir, containerName).getPath();
    if (new File(pathToSave).exists()) {
      this.log.error("Failed to save container to '" + pathToSave + "'. File already exists");
      throw new DigiDoc4JUtilityException(7, "Failed to save container to '" + pathToSave + "'. File already exists");
    }
    return pathToSave;
  }

  private File getInputDirectory() {
    return this.getDirectory(this.commandLineExecutor.getContext().getCommandLine().getOptionValue("inputDir"));
  }

  private File getOutputDirectory() {
    this.createOutputFolder(
        this.getDirectory(this.commandLineExecutor.getContext().getCommandLine().getOptionValue("outputDir")));
    return outputDir;
  }

  private File getDirectory(String outputDirPath) {
    File folder = new File(outputDirPath);
    if (folder.exists() && !folder.isDirectory()) {
      this.log.error(outputDirPath + " is not a directory");
      throw new DigiDoc4JUtilityException(6, outputDirPath + " is not a directory");
    }
    return folder;
  }

  private void createOutputFolder(File folder) {
    if (!folder.exists()) {
      this.log.debug(folder.getPath() + " directory does not exist. Creating new folder");
      folder.mkdir();
    }
  }

  private String getMimeType(String documentPath) {
    String mimeType = this.commandLineExecutor.getContext().getCommandLine().getOptionValue("mimeType");
    if (StringUtils.isNotBlank(mimeType)) {
      return mimeType;
    }
    return MimeType.fromFileName(documentPath).getMimeTypeString();
  }

}
