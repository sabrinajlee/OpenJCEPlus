/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import java.lang.reflect.*;
import java.lang.ref.Cleaner;
import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.security.ProviderException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
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
        
    private static  Runtime rt = Runtime.getRuntime();

    private static final Cleaner cleaner = Cleaner.create(new CleanerThreadFactory());

    private static Method runCleaning;

    private static final double DEFAULT_MAX_MEMORY = 0.6;

    private static final double CUSTOM_MAX_MEMORY;

    static {
        double tempMaxMem = DEFAULT_MAX_MEMORY;
        String newMaxMem = System.getProperty("my.maxMemory");

        if (newMaxMem != null){
            try {
                double parsedValue = Double.parseDouble(newMaxMem);

                if (parsedValue < 1 && parsedValue > 0){
                    tempMaxMem = parsedValue;
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
        CUSTOM_MAX_MEMORY = tempMaxMem;
    }

    static {
        try {
            Field impl = cleaner.getClass().getDeclaredField("impl");
            impl.setAccessible(true);

            Object cleanerimpl = impl.get(cleaner);

            runCleaning = cleanerimpl.getClass().getDeclaredMethod("run");
            runCleaning.setAccessible(true);
            System.out.println(runCleaning.getName());
        }
        catch (NoSuchMethodException | NoSuchFieldException | IllegalAccessException e) {    
            e.printStackTrace();
            System.exit(0);
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
        Cleaner.Cleanable newCleanable = cleaner.register(owner, cleanAction);
        if (runCleaning != null && needCleaning()){
            System.out.println("works here");
            try {
                runCleaning.invoke(cleaner);
            }
            catch (IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
                System.exit(0);
            }
        }
    }

    private static boolean needCleaning() {
        long totalMemory = rt.totalMemory();
        long usedMemory = totalMemory - rt.freeMemory();

        if (usedMemory >= (double) totalMemory * CUSTOM_MAX_MEMORY) {
            return true;
        }
        else {
            return false;
        }
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

