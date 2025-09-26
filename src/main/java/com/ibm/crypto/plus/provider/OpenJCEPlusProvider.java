/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import java.lang.ref.Cleaner;
import java.security.ProviderException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ThreadFactory;

// Internal interface for OpenJCEPlus and OpenJCEPlus implementation classes.
// Implemented as an abstract class rather than an interface so that 
// methods can be package protected, as interfaces have only public methods.
// Code is not implemented in this class to ensure that any thread call
// stacks show it originating in the specific provider class.
//
public abstract class OpenJCEPlusProvider extends java.security.Provider {
    private static final long serialVersionUID = 1L;

    private static final String PROVIDER_VER = System.getProperty("java.specification.version");

    private static final String JAVA_VER = System.getProperty("java.specification.version");

    static final String DEBUG_VALUE = "jceplus";

    static final boolean allowLegacyHKDF = Boolean.getBoolean("openjceplus.allowLegacyHKDF");

    //    private static boolean verifiedSelfIntegrity = false;
    private static final boolean verifiedSelfIntegrity = true;

    private static final Cleaner[] cleaners;

    private static final int DEFAULT_NUM_CLEANERS = 1;

    private static final int CUSTOM_NUM_CLEANERS;

    private static AtomicInteger count = new AtomicInteger(0);

    static {
        int tempNumCleaners = DEFAULT_NUM_CLEANERS;
        String newNumCleaners = System.getProperty("numCleaners");

        if (newNumCleaners != null){
            try {
                int parsedValue = Integer.parseInt(newNumCleaners);

                if (parsedValue >= 1){ // should set a max?
                    tempNumCleaners = parsedValue;
                }
                else {
                    // change this
                    System.out.println("Warning: Max memory must be set to a double between 0 and 1, default 0.6.");
                }
            }
            catch (NumberFormatException e) {
                // change this
                System.out.println("Warning: Max memory must be set to a double.");
            }
        }
        CUSTOM_NUM_CLEANERS = tempNumCleaners;
    }

    static {
        cleaners = new Cleaner[CUSTOM_NUM_CLEANERS];
        
        for (int i = 0; i < CUSTOM_NUM_CLEANERS; i++) {
            final Cleaner cleaner = Cleaner.create(new CleanerThreadFactory());
            cleaners[i] = cleaner;
        }
    }

    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);
    }

    static final boolean verifySelfIntegrity(Object c) {
        if (verifiedSelfIntegrity) {
            return true;
        }

        return doSelfVerification(c);
    }

    private static final synchronized boolean doSelfVerification(Object c) {
        return true;
    }

    public static void registerCleanable(CleanableObject owner, Runnable cleanAction) {
        Cleaner cleaner = cleaners[count.incrementAndGet() % 5];
        cleaner.register(owner, cleanAction);
    }

    // Get OCK context for crypto operations
    //
    abstract OCKContext getOCKContext();

    // Get the context associated with the provider. The context is used in
    // serialization to be able to keep track of the associated provider.
    //
    abstract ProviderContext getProviderContext();

    // Get SecureRandom to use for crypto operations. If in FIPS mode, returns a
    // FIPS
    // approved SecureRandom to use.
    //
    abstract java.security.SecureRandom getSecureRandom(
            java.security.SecureRandom userSecureRandom);

    // Return whether the provider is FIPS. If the provider is using an OCK
    // context in FIPS mode then it is FIPS.
    //
    boolean isFIPS() {
        return getOCKContext().isFIPS();
    }

    // Return the Java version.
    //
    String getJavaVersionStr() {
        return JAVA_VER;
    }

    abstract ProviderException providerException(String message, Throwable ockException);

    abstract void setOCKExceptionCause(Exception exception, Throwable ockException);

    private static class CleanerThreadFactory implements ThreadFactory {

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r);
            thread.setPriority(Thread.MAX_PRIORITY);
            return thread;
        }

    }
}

