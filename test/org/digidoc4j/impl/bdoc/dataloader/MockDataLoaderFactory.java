/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.dataloader;

import eu.europa.esig.dss.client.http.DataLoader;

public class MockDataLoaderFactory implements DataLoaderFactory {

  private DataLoader dataLoader;

  public MockDataLoaderFactory(DataLoader dataLoader) {
    this.dataLoader = dataLoader;
  }

  @Override
  public DataLoader create() {
    return dataLoader;
  }

  public DataLoader getDataLoader() {
    return dataLoader;
  }
}
