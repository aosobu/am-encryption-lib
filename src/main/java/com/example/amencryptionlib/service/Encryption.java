package com.example.amencryptionlib.service;

import java.security.GeneralSecurityException;
import org.jetbrains.annotations.NotNull;

public interface Encryption {
   @NotNull String encrypt(@NotNull String input) throws GeneralSecurityException;
   @NotNull String decrypt(@NotNull String cipherText) throws GeneralSecurityException;
}
