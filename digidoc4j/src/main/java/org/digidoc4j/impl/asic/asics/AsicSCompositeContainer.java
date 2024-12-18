/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.CompositeContainer;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.ValidatableContainer;
import org.digidoc4j.impl.asic.AsicCompositeContainerValidationResult;
import org.digidoc4j.impl.asic.AsicContainerValidationResult;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.report.TimestampValidationReport;

import java.io.File;
import java.io.InputStream;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * A special case of ASiC-S container with timestamp tokens, when the datafile of the container is a nested container.
 */
public class AsicSCompositeContainer extends AsicSContainer implements CompositeContainer {

  private static final String NOT_FOR_THIS_CONTAINER = "Not for ASiC-S container with nesting";

  private final Container nestedContainer;

  public AsicSCompositeContainer(DataFile serializedNestedContainer, Container nestedContainer) {
    this.nestedContainer = validateNestedContainer(nestedContainer);
    super.addDataFile(validateSerializedNestedContainer(serializedNestedContainer));
  }

  public AsicSCompositeContainer(DataFile serializedNestedContainer, Container nestedContainer, Configuration configuration) {
    super(configuration);
    this.nestedContainer = validateNestedContainer(nestedContainer);
    super.addDataFile(validateSerializedNestedContainer(serializedNestedContainer));
  }

  public AsicSCompositeContainer(AsicParseResult containerParseResult, Container nestedContainer, Configuration configuration) {
    super(containerParseResult, configuration);
    this.nestedContainer = validateNestedContainer(nestedContainer);
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public DataFile addDataFile(InputStream inputStream, String fileName, String mimeType) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public void removeDataFile(DataFile file) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public List<DataFile> getNestingContainerDataFiles() {
    return getDataFiles();
  }

  @Override
  public List<DataFile> getNestedContainerDataFiles() {
    return Collections.unmodifiableList(nestedContainer.getDataFiles());
  }

  @Override
  public List<Signature> getNestingContainerSignatures() {
    return getSignatures();
  }

  @Override
  public List<Signature> getNestedContainerSignatures() {
    return Collections.unmodifiableList(nestedContainer.getSignatures());
  }

  @Override
  public List<Timestamp> getNestingContainerTimestamps() {
    return getTimestamps();
  }

  @Override
  public List<Timestamp> getNestedContainerTimestamps() {
    return Collections.unmodifiableList(nestedContainer.getTimestamps());
  }

  @Override
  public String getNestedContainerType() {
    return nestedContainer.getType();
  }

  @Override
  public ContainerValidationResult validate() {
    return processValidation(super.validate());
  }

  @Override
  public ContainerValidationResult validateAt(Date validationTime) {
    return processValidation(super.validateAt(validationTime));
  }

  private ContainerValidationResult processValidation(ContainerValidationResult nestingContainerValidationResult) {
    if (nestingContainerValidationResult instanceof AsicContainerValidationResult) {
      AsicContainerValidationResult nestingContainerAsicValidationResult = (AsicContainerValidationResult) nestingContainerValidationResult;
      ContainerValidationResult nestedContainerValidationResult = validateNestedContainer(nestingContainerAsicValidationResult);

      return new AsicCompositeContainerValidationResult(nestingContainerAsicValidationResult, nestedContainerValidationResult);
    }

    throw new TechnicalException("Incompatible validation result of nesting container");
  }

  private ContainerValidationResult validateNestedContainer(AsicContainerValidationResult nestingContainerValidationResult) {
    if (nestedContainer instanceof ValidatableContainer) {
      Date validationTime = findEarliestPoeOfNestedContainer(nestingContainerValidationResult);
      if (validationTime != null) {
        return ((ValidatableContainer) nestedContainer).validateAt(validationTime);
      }
    }

    return nestedContainer.validate();
  }

  private Date findEarliestPoeOfNestedContainer(AsicContainerValidationResult nestingContainerValidationResult) {
    Date earliestPoe = null;

    for (TimestampValidationReport timestampValidationReport : nestingContainerValidationResult.getTimestampReports()) {
      if (!(isTimestampValid(timestampValidationReport) && doesTimestampCoverNestedContainer(timestampValidationReport))) {
        continue;
      }

      Date timestampProductionTime = timestampValidationReport.getProductionTime();
      if (timestampProductionTime != null && (earliestPoe == null || timestampProductionTime.before(earliestPoe))) {
        earliestPoe = timestampProductionTime;
      }
    }

    return earliestPoe;
  }

  private boolean doesTimestampCoverNestedContainer(TimestampValidationReport timestampValidationReport) {
    if (CollectionUtils.isEmpty(timestampValidationReport.getTimestampScope())) {
      return false;
    }

    String nestedContainerName = getDataFiles().get(0).getName();

    for (XmlSignatureScope timestampScope : timestampValidationReport.getTimestampScope()) {
      if (StringUtils.equals(timestampScope.getName(), nestedContainerName)) {
        return true;
      }
    }

    return false;
  }

  private static boolean isTimestampValid(TimestampValidationReport timestampValidationReport) {
    return CollectionUtils.isEmpty(timestampValidationReport.getErrors());
  }

  private static DataFile validateSerializedNestedContainer(DataFile serializedNestedContainer) {
    return Objects.requireNonNull(
            serializedNestedContainer,
            "Data file representing the nested container cannot be null"
    );
  }

  private static Container validateNestedContainer(Container nestedContainer) {
    Objects.requireNonNull(nestedContainer, "Nested container cannot be null");
    String nestedContainerType = nestedContainer.getType();
    switch (nestedContainerType) {
      case Constant.ASICE_CONTAINER_TYPE:
      case Constant.ASICS_CONTAINER_TYPE:
      case Constant.BDOC_CONTAINER_TYPE:
      case Constant.DDOC_CONTAINER_TYPE:
        return nestedContainer;
      default:
        throw new IllegalArgumentException("Unsupported nested container type: " + nestedContainerType);
    }
  }

}
