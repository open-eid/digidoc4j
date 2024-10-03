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

import java.util.List;

/**
 * An extension to the {@link Container} interface that represents a composite structure where a nested inner container
 * is contained inside a nesting outer container.
 */
public interface CompositeContainer extends Container {

  /**
   * Returns the list of data files in the nesting outer container.
   *
   * @return list of data files in the nesting outer container
   */
  List<DataFile> getNestingContainerDataFiles();

  /**
   * Returns the list of data files in the nested inner container.
   *
   * @return list of data files in the nested inner container
   */
  List<DataFile> getNestedContainerDataFiles();

  /**
   * Returns the list of signatures in the nesting outer container.
   *
   * @return list of signatures in the nesting outer container
   */
  List<Signature> getNestingContainerSignatures();

  /**
   * Returns the list of signatures in the nested inner container.
   *
   * @return list of signatures in the nested inner container
   */
  List<Signature> getNestedContainerSignatures();

  /**
   * Returns the list of timestamp tokens that cover the contents of the nesting outer container.
   *
   * @return list of timestamp tokens in the nesting outer container
   */
  List<Timestamp> getNestingContainerTimestamps();

  /**
   * Returns the list of timestamp tokens that cover the contents of the nested inner container.
   *
   * @return list of timestamp tokens in the nested inner container
   */
  List<Timestamp> getNestedContainerTimestamps();

  /**
   * Returns the type of the nested container.
   *
   * @return type of the nested container
   *
   * @see Container#getType()
   */
  String getNestedContainerType();

}
