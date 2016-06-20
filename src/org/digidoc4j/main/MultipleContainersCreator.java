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
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.MimeType;

public class MultipleContainersCreator {

  private final static Logger logger = LoggerFactory.getLogger(MultipleContainersCreator.class);

  private CommandLine commandLine;
  private final ContainerManipulator containerManipulator;
  private File inputDir;
  private File outputDir;
  private Container.DocumentType containerType;

  public MultipleContainersCreator(CommandLine commandLine) {
    this.commandLine = commandLine;
    containerManipulator = new ContainerManipulator(commandLine);
  }

  public void signDocuments() {
    inputDir = getInputDirectory();
    outputDir = getOutputDirectory();
    containerType = containerManipulator.getContainerType(commandLine);
    File[] documents = inputDir.listFiles();
    for(File document: documents) {
      if (!document.isDirectory()) {
        signDocument(document);
      } else {
        logger.debug("Skipping directory " + document.getName());
      }
    }
  }

  private void signDocument(File document) {
    String documentPath = document.getPath();
    String mimeType = MimeType.fromFileName(documentPath).getMimeTypeString();
    Container container = ContainerBuilder.
        aContainer(containerType.name()).
        withDataFile(document, mimeType).
        build();
    containerManipulator.processContainer(container);
    String pathToSave = createContainerPathToSave(document);
    containerManipulator.saveContainer(container, pathToSave);
  }

  private String createContainerPathToSave(File document) {
    String extension = containerType.name().toLowerCase();
    String containerName = FilenameUtils.removeExtension(document.getName()) + "." + extension;
    return new File(outputDir, containerName).getPath();
  }

  private File getInputDirectory() {
    String inputDirPath = commandLine.getOptionValue("inputDir");
    return getDirectory(inputDirPath);
  }

  private File getOutputDirectory() {
    String outputDirPath = commandLine.getOptionValue("outputDir");
    File outputDir = getDirectory(outputDirPath);
    createOutputDirIfNeeded(outputDir);
    return outputDir;
  }

  private File getDirectory(String outputDirPath) {
    File outputDir = new File(outputDirPath);
    if(outputDir.exists() && !outputDir.isDirectory()) {
      logger.error(outputDirPath + " is not a directory");
      throw new DigiDoc4JUtilityException(6, outputDirPath + " is not a directory");
    }
    return outputDir;
  }

  private void createOutputDirIfNeeded(File outputDir) {
    if(!outputDir.exists()) {
      logger.debug(outputDir.getPath() + " directory does not exist. Creating new directory");
      outputDir.mkdir();
    }
  }
}
