package org.digidoc4j;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.Helper;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Ignore;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.digidoc4j.ContainerInterface.DocumentType.DDOC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ContainerTest {
  public static final String TEXT_MIME_TYPE = "text/plain";

  public static final String CERTIFICATE =
    "MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhkiG9w0BAQUFADB9\n" +
    "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\n" +
    "czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290\n" +
    "IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMTEwMzA3MTMyMjQ1WhcN\n" +
    "MjQwOTA3MTIyMjQ1WjCBgzELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRp\n" +
    "Zml0c2VlcmltaXNrZXNrdXMxDTALBgNVBAsMBE9DU1AxJzAlBgNVBAMMHlRFU1Qg\n" +
    "b2YgU0sgT0NTUCBSRVNQT05ERVIgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNr\n" +
    "LmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cw6Cja17BbYbHi6\n" +
    "frwccDI4BIQLk/fiCE8L45os0xhPgEGR+EHE8LPCIqofPgf4gwN1vDE6cQNUlK0O\n" +
    "d+Ush39i9Z45esnfpGq+2HsDJaFmFr5+uC1MEz5Kn1TazEvKbRjkGnSQ9BertlGe\n" +
    "r2BlU/kqOk5qA5RtJfhT0psc1ixKdPipv59wnf+nHx1+T+fPWndXVZLoDg4t3w8l\n" +
    "IvIE/KhOSMlErvBIHIAKV7yH1hOxyeGLghqzMiAn3UeTEOgoOS9URv0C/T5C3mH+\n" +
    "Y/uakMSxjNuz41PneimCzbEJZJRiEaMIj8qPAubcbL8GtY03MWmfNtX6/wh6u6TM\n" +
    "fW8S2wIDAQABo4H+MIH7MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMJMB0GA1UdDgQW\n" +
    "BBR9/5CuRokEgGiqSzYuZGYAogl8TzCBoAYDVR0gBIGYMIGVMIGSBgorBgEEAc4f\n" +
    "AwEBMIGDMFgGCCsGAQUFBwICMEweSgBBAGkAbgB1AGwAdAAgAHQAZQBzAHQAaQBt\n" +
    "AGkAcwBlAGsAcwAuACAATwBuAGwAeQAgAGYAbwByACAAdABlAHMAdABpAG4AZwAu\n" +
    "MCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LnNrLmVlL2FqYXRlbXBlbC8wHwYDVR0j\n" +
    "BBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wDQYJKoZIhvcNAQEFBQADggEBAAba\n" +
    "j7kTruTAPHqToye9ZtBdaJ3FZjiKug9/5RjsMwDpOeqFDqCorLd+DBI4tgdu0g4l\n" +
    "haI3aVnKdRBkGV18kqp84uU97JRFWQEf6H8hpJ9k/LzAACkP3tD+0ym+md532mV+\n" +
    "nRz1Jj+RPLAUk9xYMV7KPczZN1xnl2wZDJwBbQpcSVH1DjlZv3tFLHBLIYTS6qOK\n" +
    "4SxStcgRq7KdRczfW6mfXzTCRWM3G9nmDei5Q3+XTED41j8szRWglzYf6zOv4djk\n" +
    "ja64WYraQ5zb4x8Xh7qTCk6UupZ7je+0oRfuz0h/3zyRdjcRPkjloSpQp/NG8Rmr\n" +
    "cnr874p8d9fdwCrRI7U=\n";

  //TODO maybe it is good idea to put it to separate file
  private static String signature =
    "  <Signature Id=\"S1\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
    "    <SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
    "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n" +
    "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n" +
    "      <Reference URI=\"#D0\">\n" +
    "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n" +
    "        <DigestValue>PKkcL8LlT9S1BO+HdXjb2djNzrM=</DigestValue>\n" +
    "      </Reference>\n" +
    "      <Reference Type=\"http://uri.etsi.org/01903/v1.1.1#SignedProperties\" URI=\"#S1-SignedProperties\">\n" +
    "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n" +
    "        <DigestValue>UOK/V3cCbuo/kRTtgTWuYLm2wJA=</DigestValue>\n" +
    "      </Reference>\n" +
    "    </SignedInfo>\n" +
    "    <SignatureValue Id=\"S1-SIG\">\n" +
    "      RQ13qS4+2eqas4MS9rz4dKXqIEKMoXBWHGU0/TOtBk2sRST+ItOChpRn+xRIFg13vSzjKIZHhnTYHuNRSmMLPFWD1UiXU68sqnBDzpI5f2db1FXC7OniGthZDwHWuGg1gBsqtW7tOfSpSQREYzP86amzY/lf1CLECPqC+Up886dyNjWccSQf1CaYtSneEUNpJP2XQhlMf22bOvL8wq76dvudl3jx2HJErqyz0TObQXYLsQQGSYGN7JhdDQvYwTEYNIz/NCu1K/Wn+HuIUZCZnh1KqQt7KZSX186MilkCXSBEM+PHEd/7qOyJYTnwJFYp6sTDO4ntAUq3ZDMHM4qE2g==\n" +
    "    </SignatureValue>\n" +
    "    <KeyInfo>\n" +
    "      <KeyValue>\n" +
    "        <RSAKeyValue>\n" +
    "          <Modulus>AKGf2pVoD7HdGQMGsPm6PB+et4rn81v42+j1WDk4syfckpShSEVfoD+rmUFTKUr8\n" +
    "            JT+U1FO/+SJyqe7VoLICJbRdViTyOs4jXBFsd7IEyr/mBWb+9ttG0yL9cYuSAxnl\n" +
    "            QPFjRBl+a7zCVEnzXrjNE2hy5QkstdY4Hq91rZFFcLcKLHhMO9DAaY+tBAnx3MMg\n" +
    "            kSQtLs0IsFNyd2btu5B6BFzTjeAoyNSZGEZkTMXiglrikx9ep5Jr49S2s3I001Bo\n" +
    "            7BMfb1HxoV8ZTbGitW/GhSJ42KnJYwTPwFNQbDAhx5qlaLvuWgFX9VB9K1edA27+\n" +
    "            zoELTiyzjc7qwrvQwHWqVFk=\n" +
    "          </Modulus>\n" +
    "          <Exponent>AQAB</Exponent>\n" +
    "        </RSAKeyValue>\n" +
    "      </KeyValue>\n" +
    "      <X509Data>\n" +
    "        <X509Certificate>MIIFEzCCA/ugAwIBAgIQSXxaK/qTYahTT77Z9I56EjANBgkqhkiG9w0BAQUFADBs\n" +
    "          MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\n" +
    "          czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJ\n" +
    "          ARYJcGtpQHNrLmVlMB4XDTE0MDQxNzExNDUyOVoXDTE2MDQxMjIwNTk1OVowgbQx\n" +
    "          CzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxGjAYBgNVBAsMEWRpZ2l0YWwg\n" +
    "          c2lnbmF0dXJlMTEwLwYDVQQDDCjFvcOVUklOw5xXxaBLWSxNw4RSw5wtTMOWw5Za\n" +
    "          LDExNDA0MTc2ODY1MRcwFQYDVQQEDA7FvcOVUklOw5xXxaBLWTEWMBQGA1UEKgwN\n" +
    "          TcOEUsOcLUzDlsOWWjEUMBIGA1UEBRMLMTE0MDQxNzY4NjUwggEiMA0GCSqGSIb3\n" +
    "          DQEBAQUAA4IBDwAwggEKAoIBAQChn9qVaA+x3RkDBrD5ujwfnreK5/Nb+Nvo9Vg5\n" +
    "          OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqnu1aCyAiW0XVYk8jrOI1wRbHey\n" +
    "          BMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJLLXWOB6vda2R\n" +
    "          RXC3Cix4TDvQwGmPrQQJ8dzDIJEkLS7NCLBTcndm7buQegRc043gKMjUmRhGZEzF\n" +
    "          4oJa4pMfXqeSa+PUtrNyNNNQaOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGww\n" +
    "          IceapWi77loBV/VQfStXnQNu/s6BC04ss43O6sK70MB1qlRZAgMBAAGjggFmMIIB\n" +
    "          YjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDCBmQYDVR0gBIGRMIGOMIGLBgor\n" +
    "          BgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuAHUAbAB0ACAAdABlAHMA\n" +
    "          dABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAAZgBvAHIAIAB0AGUAcwB0AGkA\n" +
    "          bgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAdBgNVHQ4E\n" +
    "          FgQUEjVsOkaNOGG0GlcF4icqxL0u4YcwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYB\n" +
    "          ATAIBgYEAI5GAQQwHwYDVR0jBBgwFoAUQbb+xbGxtFMTjPr6YtA0bW0iNAowRQYD\n" +
    "          VR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5zay5lZS9yZXBvc2l0b3J5L2NybHMv\n" +
    "          dGVzdF9lc3RlaWQyMDExLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAYTJLbScA3+Xh\n" +
    "          /s29Qoc0cLjXW3SVkFP/U71/CCIBQ0ygmCAXiQIp/7X7JonY4aDz5uTmq742zZgq\n" +
    "          5FA3c3b4NtRzoiJXFUWQWZOPE6Ep4Y07Lpbn04sypRKbVEN9TZwDy3elVq84BcX/\n" +
    "          7oQYliTgj5EaUvpe7MIvkK4DWwrk2ffx9GRW+qQzzjn+OLhFJbT/QWi81Q2CrX34\n" +
    "          GmYGrDTC/thqr5WoPELKRg6a0v3mvOCVtfIxJx7NKK4B6PGhuTl83hGzTc+Wwbax\n" +
    "          wjqzl/SUwCNd2R8GV8EkhYH8Kay3Ac7Qx3agrJJ6H8j+h+nCKLjIdYImvnznKyR0\n" +
    "          N2CRc/zQ+g==\n" +
    "        </X509Certificate>\n" +
    "      </X509Data>\n" +
    "    </KeyInfo>\n" +
    "    <Object>\n" +
    "      <QualifyingProperties Target=\"#S1\" xmlns=\"http://uri.etsi.org/01903/v1.1.1#\">\n" +
    "        <SignedProperties Id=\"S1-SignedProperties\">\n" +
    "          <SignedSignatureProperties>\n" +
    "            <SigningTime>2014-06-13T09:50:06Z</SigningTime>\n" +
    "            <SigningCertificate>\n" +
    "              <Cert>\n" +
    "                <CertDigest>\n" +
    "                  <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n" +
    "                  <DigestValue>N9OdruanX8xd0jmQiqaTjnIb7Mk=</DigestValue>\n" +
    "                </CertDigest>\n" +
    "                <IssuerSerial>\n" +
    "                  <X509IssuerName\n" +
    "                    xmlns=\"http://www.w3.org/2000/09/xmldsig#\">1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=TEST of ESTEID-SK 2011,O=AS Sertifitseerimiskeskus,C=EE\n" +
    "                  </X509IssuerName>\n" +
    "                  <X509SerialNumber xmlns=\"http://www.w3.org/2000/09/xmldsig#\">97679317403981919837045055800589842962</X509SerialNumber>\n" +
    "                </IssuerSerial>\n" +
    "              </Cert>\n" +
    "            </SigningCertificate>\n" +
    "            <SignaturePolicyIdentifier>\n" +
    "              <SignaturePolicyImplied></SignaturePolicyImplied>\n" +
    "            </SignaturePolicyIdentifier>\n" +
    "            <SignatureProductionPlace></SignatureProductionPlace>\n" +
    "          </SignedSignatureProperties>\n" +
    "          <SignedDataObjectProperties></SignedDataObjectProperties>\n" +
    "        </SignedProperties>\n" +
    "        <UnsignedProperties xmlns=\"http://uri.etsi.org/01903/v1.1.1#\">\n" +
    "          <UnsignedSignatureProperties>\n" +
    "            <CompleteCertificateRefs Id=\"S1-CERTREFS\">\n" +
    "              <CertRefs>\n" +
    "                <Cert>\n" +
    "                  <CertDigest>\n" +
    "                    <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n" +
    "                    <DigestValue>fQUNlFAUBPUsq/i/n/1zf1WVQqw=</DigestValue>\n" +
    "                  </CertDigest>\n" +
    "                  <IssuerSerial>\n" +
    "                    <X509IssuerName\n" +
    "                      xmlns=\"http://www.w3.org/2000/09/xmldsig#\">1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=TEST of EE Certification Centre Root CA,O=AS Sertifitseerimiskeskus,C=EE\n" +
    "                    </X509IssuerName>\n" +
    "                    <X509SerialNumber xmlns=\"http://www.w3.org/2000/09/xmldsig#\">138983222239407220571566848351990841243</X509SerialNumber>\n" +
    "                  </IssuerSerial>\n" +
    "                </Cert>\n" +
    "              </CertRefs>\n" +
    "            </CompleteCertificateRefs>\n" +
    "            <CompleteRevocationRefs Id=\"S1-REVOCREFS\">\n" +
    "              <OCSPRefs>\n" +
    "                <OCSPRef>\n" +
    "                  <OCSPIdentifier URI=\"#N1\">\n" +
    "                    <ResponderID>C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=TEST of SK OCSP RESPONDER 2011,E=pki@sk.ee</ResponderID>\n" +
    "                    <ProducedAt>2014-06-13T09:50:06Z</ProducedAt>\n" +
    "                  </OCSPIdentifier>\n" +
    "                  <DigestAlgAndValue>\n" +
    "                    <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n" +
    "                    <DigestValue>4LqK0iBlmpiwRVkNW0PXMID8zZE=</DigestValue>\n" +
    "                  </DigestAlgAndValue>\n" +
    "                </OCSPRef>\n" +
    "              </OCSPRefs>\n" +
    "            </CompleteRevocationRefs>\n" +
    "            <CertificateValues>\n" +
    "              <EncapsulatedX509Certificate Id=\"S1-RESPONDER_CERT\">\n" +
    CERTIFICATE +
    "              </EncapsulatedX509Certificate>\n" +
    "            </CertificateValues>\n" +
    "            <RevocationValues>\n" +
    "              <OCSPValues>\n" +
    "                <EncapsulatedOCSPValue Id=\"N1\">\n" +
    "                  MIICWwoBAKCCAlQwggJQBgkrBgEFBQcwAQEEggJBMIICPTCCASWhgYYwgYMxCzAJ\n" +
    "                  BgNVBAYTAkVFMSIwIAYDVQQKDBlBUyBTZXJ0aWZpdHNlZXJpbWlza2Vza3VzMQ0w\n" +
    "                  CwYDVQQLDARPQ1NQMScwJQYDVQQDDB5URVNUIG9mIFNLIE9DU1AgUkVTUE9OREVS\n" +
    "                  IDIwMTExGDAWBgkqhkiG9w0BCQEWCXBraUBzay5lZRgPMjAxNDA2MTMwOTUwMDZa\n" +
    "                  MGAwXjBJMAkGBSsOAwIaBQAEFJlSx0SY5H6TNo4LfCcJivmxW5RQBBRBtv7FsbG0\n" +
    "                  UxOM+vpi0DRtbSI0CgIQSXxaK/qTYahTT77Z9I56EoAAGA8yMDE0MDYxMzA5NTAw\n" +
    "                  NlqhJzAlMCMGCSsGAQUFBzABAgQWBBSgQ/a9YzY4QSbzrnXGUG4GxX7SOjANBgkq\n" +
    "                  hkiG9w0BAQUFAAOCAQEAnKwDAMXHB7lRNXRS9QBDdfwuNZkZPGUGImN/ZGXyVWNE\n" +
    "                  2xY+FRg4ADgxzJVHLHp6CdH50pLdeQHpvI5OS7g7P8XhXEkDmt5QwHyi+iDP72Cn\n" +
    "                  cPKTgWI7C23c417v8NcxaHAkiWpe/RwKpEQ5BNqC0sI25N5UuKVFN+Qm7KxTQ/Do\n" +
    "                  +oZC8rEBfuaR9L9DTEQA3rLbNPZIFPc3wpv6aBMBLq/O7p23TCiLXGiz/Yl0yuSx\n" +
    "                  zu/xL4NiBprD23Q3jiDAu9SsskPGrgwh36v+I7rYzSbj8bKEjKdf+dY3QO+9Egoe\n" +
    "                  TaMmSTFSra3zxjAo82vlegR/KFl/Dr/JJiPN6+xbhw==\n" +
    "                </EncapsulatedOCSPValue>\n" +
    "              </OCSPValues>\n" +
    "            </RevocationValues>\n" +
    "          </UnsignedSignatureProperties>\n" +
    "        </UnsignedProperties>\n" +
    "      </QualifyingProperties>\n" +
    "    </Object>\n" +
    "  </Signature>";

  @Test
  public void testAddOneFileToContainerForBDoc() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", TEXT_MIME_TYPE);
    List<DataFile> dataFiles = bDocContainer.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(new File("test.txt").getAbsolutePath(), dataFiles.get(0).getFileName());
    assertEquals(TEXT_MIME_TYPE, dataFiles.get(0).getMediaType());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddDataFileFromInputStreamToContainerForBDoc() throws Exception {
    Container container = new Container();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x41}), "test.txt", TEXT_MIME_TYPE);
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForBDoc() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", TEXT_MIME_TYPE);
    bDocContainer.removeDataFile("test.txt");
    assertEquals(0, bDocContainer.getDataFiles().size());
  }

  @Test
  @Ignore("Not working in Ubuntu check later when jDigiDoc is implemented.")
  public void testCreateAsicContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container asicContainer = new Container(Container.DocumentType.ASIC);
    asicContainer.addDataFile("test.txt", TEXT_MIME_TYPE);
    asicContainer.sign(new PKCS12Signer("signout.p12", "test"));
    asicContainer.save("test.bdoc");
    assertTrue(Helper.isZipFile(new File("test.bdoc")));
  }

  @Test
  public void testCreateDDocContainer() throws Exception {
    Container dDocContainer = new Container(DDOC);
    dDocContainer.addDataFile("test.txt", TEXT_MIME_TYPE);
    dDocContainer.sign(new PKCS12Signer("signout.p12", "test"));
    dDocContainer.save("test.ddoc");
    assertTrue(Helper.isXMLFile(new File("test.ddoc")));
  }

  @Test
  public void testAddOneFileToContainerForDDoc() throws Exception {
    Container container = new Container(DDOC);
    container.addDataFile("test.txt", TEXT_MIME_TYPE);
    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(new File("test.txt").getAbsolutePath(), dataFiles.get(0).getFileName());
    assertEquals(TEXT_MIME_TYPE, dataFiles.get(0).getMediaType());
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForDDoc() throws Exception {
    Container container1 = new Container(DDOC);
    container1.addDataFile("test.txt", TEXT_MIME_TYPE);
    Container container = container1;
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testOpenCreatedDDocFile() throws Exception {
    Container container1 = new Container(DDOC);
    container1.addDataFile("test.txt", TEXT_MIME_TYPE);
    Container container = container1;
    container.save("testOpenCreatedDDocFile.ddoc");
    Container containerForReading = new Container("testOpenCreatedDDocFile.ddoc");
    assertEquals(DDOC, containerForReading.getDocumentType());
    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidFileThrowsException() {
    new Container("test.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenNotExistingFileThrowsException() {
    new Container("noFile.ddoc");
  }

  @Test
  public void testAddFileFromStreamToDDoc() {
    Container container = new Container(DDOC);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "testFromStream.txt", TEXT_MIME_TYPE);
    DataFile dataFile = container.getDataFiles().get(0);
    assertEquals("testFromStream.txt", dataFile.getFileName());
  }

  @Test
  public void testGetSignatureFromDDoc() {
    Container container = new Container(DDOC);
    container.addDataFile("test.txt", TEXT_MIME_TYPE);
    container.sign(new PKCS12Signer("signout.p12", "test"));
    List<Signature> signatures = container.getSignatures();
    assertEquals(1, signatures.size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignatureThrowsException() {
    Container container = new Container(DDOC);
    container.addRawSignature(new byte[]{0x42});
  }

  @Test
  public void testAddRawSignatureAsByteArray() throws CertificateEncodingException {
    Container container = new Container(DDOC);
    container.addDataFile("test.txt", TEXT_MIME_TYPE);
    container.sign(new PKCS12Signer("signout.p12", "test"));
    container.addRawSignature(signature.getBytes());

    assertEquals(2, container.getSignatures().size());
    assertEquals(CERTIFICATE.replaceAll("\\s", ""), Base64.encodeBase64String(getSigningCertificateAsBytes(container, 1)));
  }

  @Test
  public void testAddRawSignatureAsStreamArray() throws CertificateEncodingException {
    Container container = new Container(DDOC);
    container.addDataFile("test.txt", TEXT_MIME_TYPE);
    container.addRawSignature(new ByteArrayInputStream(signature.getBytes()));

    assertEquals(1, container.getSignatures().size());
    assertEquals(CERTIFICATE.replaceAll("\\s", ""), Base64.encodeBase64String(getSigningCertificateAsBytes(container, 0)));
  }

  private byte[] getSigningCertificateAsBytes(Container container, int index) throws CertificateEncodingException {
    Signature signature = container.getSignatures().get(index);
    return signature.getSigningCertificate().getX509Certificate().getEncoded();
  }

  @Test
  public void testRemoveSignature() {
    Container container = new Container(DDOC);
    container.addDataFile("test.txt", TEXT_MIME_TYPE);
    container.sign(new PKCS12Signer("signout.p12", "test"));
    container.addRawSignature(new ByteArrayInputStream(signature.getBytes()));
    container.save("testRemoveSignature.ddoc");

    Container containerToRemoveSignature = new Container("testRemoveSignature.ddoc");
    containerToRemoveSignature.removeSignature(1);
    assertEquals(1, containerToRemoveSignature.getSignatures().size());
    //todo check is correct signature removed by signing time?
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNotExistingSignatureThrowsException() {
    Container container = new Container(DDOC);
    container.removeSignature(0);
  }


  public void testSigningWithSignerInfo() throws Exception {
    String city = "myCity";
    String stateOrProvince = "myStateOrProvince";
    String postalCode = "myPostalCode";
    String country = "myCountry";
    String signerRoles = "myRole / myResolution";

    PKCS12Signer signer = new PKCS12Signer("signout.p12", "test");
    signer.setSignatureProductionPlace(city, stateOrProvince, postalCode, country);
    signer.setSignerRoles(asList(signerRoles));

    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", TEXT_MIME_TYPE);
    Signature signature = bDocContainer.sign(signer);
  }

  public void testSigningWithOnlyLocationInfo() throws Exception {
  }

  public void testSigningWithPartialSignerInfo() throws Exception {
  }

  public void testSigningWithOnlySignerRole() throws Exception {
  }
}


