package prototype;

import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;

/**
 * Ths is the MOCK source which can load any trusted list.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class MockTSLCertificateSource extends TrustedListsCertificateSource {

    @Override
    protected void loadAdditionalLists(final String... urls) {

        for (final String url : urls) {

            loadTSL(url, "MOCK", null);
        }
    }
}
