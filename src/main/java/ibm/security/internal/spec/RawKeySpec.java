/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.security.internal.spec;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * This is here for easier compatibility with OpenJDK 21 and above.
 * 
 * This is a KeySpec that is used to specify a key by its byte array implementation. Since the
 * new PQC algs the bytes are defined as byte arrays.
 */
public class RawKeySpec implements KeySpec {
    private OpenJCEPlusProvider provider;
    private byte[] keyBytes = null;
    /**
     * @param key contains the key as a byte array
     */
    public RawKeySpec(byte[] key, OpenJCEPlusProvider provider) {
        keyBytes = key.clone();
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(keyBytes));
    }

    /**
     * @return a copy of the key bits
     */
    public byte[] getKeyArr() {
        return keyBytes.clone();
    }

    private Runnable cleanOCKResources(byte[] keyBytes) {
        return() -> {
            try {
                if (keyBytes != null) {
                    Arrays.fill(keyBytes, 0, keyBytes.length, (byte) 0);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
