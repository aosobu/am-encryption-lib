package com.example.amencryptionlib.service;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.example.amencryptionlib.util.CryptoUtil;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

@Service
public class AESGcmEncryption implements Encryption {

  static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
  static final int BIT_LENGTH =  128;
  static final int IV_LENGTH_BYTE = 16;

  /**
   * method encrypts string using the AES scheme defined in the
   * constant ENCRYPTION_ALGORITHM or specified by the class name
   *
   * @param input plaint text to be encrypted
   * @return encrypted string
   * @throws GeneralSecurityException when an error occurs during method invocation
   */
  @Override
  public @NotNull String encrypt(@NotNull String input)
      throws GeneralSecurityException {

    Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
    byte[] initVector = CryptoUtil.generateInitializationVector();

    cipher.init(Cipher.ENCRYPT_MODE, CryptoUtil.getAESKeyFromPassword(), new GCMParameterSpec(BIT_LENGTH, initVector));
    byte[] cipherText = cipher.doFinal(input.getBytes());
    byte[] cipherTextPrependedWithInitVector = ByteBuffer.allocate(initVector.length + cipherText.length)
                                                          .put(initVector)
                                                          .put(cipherText)
                                                          .array();

    return Base64.getEncoder().encodeToString(cipherTextPrependedWithInitVector);
  }

  /**
   * deciphers encrypted text
   *
   * @param cipherText is the encrypted text
   * @return plain text after decryption of cipher text
   * @throws GeneralSecurityException when an error occurs during method invocation
   */
  @Override
  public @NotNull String decrypt(@NotNull String cipherText)
      throws GeneralSecurityException {

    byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);
    ByteBuffer byteBuffer = ByteBuffer.wrap(decodedCipherText);

    byte[] initVectorFromCipherText = new byte[IV_LENGTH_BYTE];
    byteBuffer.get(initVectorFromCipherText);

    byte[] cipherTextWithoutInitVector = new byte[byteBuffer.remaining()];
    byteBuffer.get(cipherTextWithoutInitVector);

    Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, CryptoUtil.getAESKeyFromPassword(), new GCMParameterSpec(BIT_LENGTH, initVectorFromCipherText));
    byte[] plainText = cipher.doFinal(cipherTextWithoutInitVector);

    return new String(plainText, UTF_8);
  }
}
