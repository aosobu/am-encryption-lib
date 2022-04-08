package com.example.amencryptionlib;

import com.example.amencryptionlib.service.AESGcmEncryption;
import java.security.GeneralSecurityException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class AESGcmEncryptionTest {

  private static String cipherTextCache;
  private static final String input = "adewale.osobu@ng.airtel.com";
  private AESGcmEncryption aesGcmEncryption;

  @Before
  public void init(){
    aesGcmEncryption = new AESGcmEncryption();
  }

  @Test
  public void givenString_whenEncrypt_thenSuccess()
      throws GeneralSecurityException {
    cipherTextCache = aesGcmEncryption.encrypt(input);
    Assert.assertNotEquals(input, cipherTextCache);
  }

  @Test
  public void givenCipherText_whenDecrypt_thenSuccess()
      throws GeneralSecurityException {
    Assert.assertEquals(aesGcmEncryption.decrypt(cipherTextCache), input);
  }
}
