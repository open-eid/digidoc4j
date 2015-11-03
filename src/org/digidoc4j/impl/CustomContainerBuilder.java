/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import java.io.InputStream;
import java.lang.reflect.Constructor;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomContainerBuilder extends ContainerBuilder {

  private static final Logger logger = LoggerFactory.getLogger(CustomContainerBuilder.class);

  private String containerType;

  public CustomContainerBuilder(String containerType) {
    this.containerType = containerType;
  }

  protected Container createNewContainer() {
    if (configuration != null) {
      return instantiateContainer(configuration);
    }
    return instantiateContainer();
  }

  protected Container openContainerFromFile() {
    if (configuration != null) {
      return instantiateContainer(containerFilePath, configuration);
    }
    return instantiateContainer(containerFilePath);
  }

  protected Container openContainerFromStream() {
    if (configuration == null) {
      Class<?>[] parameterTypes = new Class[]{InputStream.class};
      Object[] constructorArguments = new Object[]{containerInputStream};
      return instantiateContainer(parameterTypes, constructorArguments);
    }
    Class<?>[] parameterTypes = new Class[]{InputStream.class, Configuration.class};
    Object[] constructorArguments = new Object[]{containerInputStream, configuration};
    return instantiateContainer(parameterTypes, constructorArguments);
  }

  @Override
  public ContainerBuilder usingTempDirectory(String temporaryDirectoryPath) {
    logger.warn("Custom containers don't support setting temp directories");
    return this;
  }

  private Container instantiateContainer(Object... constructorArguments) {
    Class<?>[] parameterTypes = assembleParameterTypes(constructorArguments);
    return instantiateContainer(parameterTypes, constructorArguments);
  }

  private Container instantiateContainer(Class<?>[] parameterTypes, Object[] constructorArguments) {
    Class<? extends Container> containerClass = getContainerClass();
    logger.debug("Instantiating " + containerType + " container from class " + containerClass.getName());
    try {
      if (constructorArguments == null || constructorArguments.length == 0) {
        return containerClass.newInstance();
      } else {
        Constructor<? extends Container> constructor = containerClass.getConstructor(parameterTypes);
        return constructor.newInstance(constructorArguments);
      }
    } catch (NoSuchMethodException e) {
      logger.error("Unable to instantiate " + containerType + " container from class " + containerClass.getName() +
          " - The class must be public and should have a default constructor and a constructor with Configuration parameter available.");
      throw new TechnicalException("Unable to instantiate " + containerType + " container from class " + containerClass.getName(), e);
    } catch (ReflectiveOperationException e) {
      logger.error("Unable to instantiate " + containerType + " container from class " + containerClass.getName());
      throw new TechnicalException("Unable to instantiate " + containerType + " container from class " + containerClass.getName(), e);
    }
  }

  private Class<?>[] assembleParameterTypes(Object[] constructorArguments) {
    Class<?>[] paramTypes = new Class<?>[constructorArguments.length];
    int index = 0;
    for (Object argument : constructorArguments) {
      paramTypes[index] = argument.getClass();
      index++;
    }
    return paramTypes;
  }

  private Class<? extends Container> getContainerClass() {
    return containerImplementations.get(containerType);
  }
}
