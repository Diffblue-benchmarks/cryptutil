package ch.dvbern.lib.cryptutil.readers;

import ch.dvbern.lib.cryptutil.readers.PKCS8PEMCertReader;
import java.security.interfaces.RSAPrivateKey;
import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.Test;

import static ch.dvbern.lib.cryptutil.TestingUtil.resourceURL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PKCS8PEMCertReaderTest {

  @Test
  public void test_readPublicKey() throws IOException {
    final URL privateKeyURL = resourceURL("signing/testkey-nopass-pkcs8.pem");

    final RSAPrivateKey key = new PKCS8PEMKeyReader(privateKeyURL.openStream(), null).readPrivateKey();
    assertEquals("RSA", key.getAlgorithm());
    assertEquals("PKCS#8", key.getFormat());
  }

  @Test
  public void test_readPublicKeyInvalidPassword() throws IOException {
    final URL privateKeyURL = resourceURL("signing/testkey-nopass-pkcs8.pem");
    
    final ReaderException thrown = 
      assertThrows(ReaderException.class, () -> new PKCS8PEMKeyReader(privateKeyURL.openStream(), "foo").readPrivateKey());
    assertEquals("Could not read PKCS8EncodedPEM", thrown.getMessage());
  }
}

