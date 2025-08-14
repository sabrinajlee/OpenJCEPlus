/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.lang.ref.Cleaner;
import java.lang.ref.WeakReference;
import java.lang.ref.PhantomReference;
import java.security.ProviderException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.Queue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.lang.ref.ReferenceQueue;

import com.ibm.crypto.plus.provider.ock.OCKContext;

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
                    System.out.println("Warning: Max memory must be set to a double between 0 and 1, default 0.6.");
                }
            }
            catch (NumberFormatException e) {
                System.out.println("Warning: Max memory must be set to a double.");
            }
        }
	CUSTOM_MAX_MEMORY = tempMaxMem;
    }



    static final String DEBUG_VALUE = "jceplus";

    //    private static boolean verifiedSelfIntegrity = false;
    private static final boolean verifiedSelfIntegrity = true;

//    private static final Cleaner cleaner = Cleaner.create();

    private static final Cleaner cleaner = Cleaner.create(new CleanerThreadFactory());

    private static final AtomicInteger counter = new AtomicInteger(0);

    private static final ConcurrentHashMap<PhantomReference<CleanableObject>, Cleaner.Cleanable> map = new ConcurrentHashMap<>();
    
    private static  Runtime rt = Runtime.getRuntime();

    private static final ReentrantLock lock = new ReentrantLock();

    private static final ReferenceQueue<CleanableObject> queue = new ReferenceQueue<>();


    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);
    }

    static final boolean verifySelfIntegrity(Object c) {
        if (verifiedSelfIntegrity) {
            return true;
        }

        return doSelfVerification(c);
    }

    public static void registerCleanableC(Object owner, WeakReference<CleanableObject> ownerRef) {
        cleaner.register(owner, new Runnable() {
            @Override
            public void run() {
                ownerRef.get().cleanup();
            }
         });
    }

    public static void registerCleanableB(Object owner, Runnable cleanAction) {
        cleaner.register(owner, cleanAction);
    }

    public static void registerCleanableB(CleanableObject owner, Runnable cleanAction) {
        Cleaner.Cleanable newCleanable = cleaner.register(owner, cleanAction);
        addCleanableToMap(newCleanable, owner);
    }

    private static void addCleanableToMap(Cleaner.Cleanable cleanable, CleanableObject owner) {
        long totalMemory = rt.totalMemory();
        long freeMemory = rt.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        PhantomReference<CleanableObject> ownerRef = new PhantomReference<>(owner, queue);

        map.put(ownerRef,cleanable);
        
//	System.out.println("\n\n\nTOTAL MEMORY: " + totalMemory + "\n FREE MEMORY: " + freeMemory + "\n\n\n");

        if (map.size() % 100000 == 0){
            System.out.println("THERE ARE " + map.size() + " ITEMS WAITING TO BE CLEANED");
            System.out.println("***** USED " + (double) usedMemory / totalMemory * 100 + "% OF MEMORY *******");
	}

        if (usedMemory >= (double) totalMemory * CUSTOM_MAX_MEMORY) {
            clearMapItems();
        }
    }


    private static void clearMapItems() {
//        if (lock.tryLock()){
//            try {
                PhantomReference<CleanableObject> ownerRef = (PhantomReference<CleanableObject>) queue.poll();
                while (ownerRef != null){
                    Cleaner.Cleanable cleanable = map.get(ownerRef);
                    if (cleanable != null) {
                        map.remove(ownerRef, cleanable);
                        cleanable.clean();
                        System.out.println("deleted 1");
                    }
                    else {
                        System.out.println("Something went wrong: No cleanable mapped to this reference");
                    }
                    ownerRef = (PhantomReference<CleanableObject>) queue.poll();
                }
//            }
//            finally {
//                lock.unlock();
//            }
//        }
//        else {
           // System.out.print("Skip!");
//        }
    }

    public static void registerCleanable(CleanableObject owner) {
        cleaner.register(owner, new Runnable() {
            @Override
            public void run() {
                owner.cleanup();
            }
        });
    }

    private static final synchronized boolean doSelfVerification(Object c) {
        return true;
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
      

