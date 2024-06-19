/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.ibm.crypto.plus.provider.CleanableObject;
import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

@SuppressWarnings({"removal", "deprecation"})
public final class Digest implements Cloneable, CleanableObject {

    /* ===========================================================================
       Digest caching mechanism
       Cache native SHA* digest contexts so that the same contexts could be reused later after resetting.
       */

    static private class Resources {
        // index corresponding the SHA algorithm it's using
        // also used as a flag:
        // 0 - 4: it is using one of {SHA1, SHA224, SHA256, SHA384, SHA512}
        // -1   : Not initialized
        // -2   : Not a SHA* digest algorithm
        private int algIndx = -1;
        private boolean contextFromQueue = false;

        private long digestId = 0;
        private OCKContext ockContext = null;

        private boolean needsReinit = false;

        private final String badIdMsg = "Digest Identifier is not valid";

        public void reset() throws OCKException {
            // reset now to make sure all contexts in the queue are ready to use
            //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);

            if (this.digestId == 0) {
                return;
            }

            if (!validId(this.digestId)) {
                throw new OCKException(badIdMsg);
            }
            if (this.needsReinit) {
                NativeInterface.DIGEST_reset(this.ockContext.getId(), this.digestId);
            }
        }

        private void cleanup() {
            //final String methodName = "finalize";

            //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);
            try {
                if (this.digestId == 0) {
                    return;
                }

                // not SHA* algorithm
                if (this.algIndx == -2) {
                    if (validId(this.digestId)) {
                        NativeInterface.DIGEST_delete(this.ockContext.getId(),
                                this.digestId);
                        this.digestId = 0;
                    }
                } else {
                    if (this.contextFromQueue) {
                        reset();

                        this.needsReinit = false;
                        contexts[this.algIndx].add(this.digestId);
                        this.digestId = 0;
                        this.contextFromQueue = false;
                    } else {
                        // delete context
                        if (validId(this.digestId)) {
                            NativeInterface.DIGEST_delete(this.ockContext.getId(),
                                    this.digestId);
                            this.digestId = 0;
                        }
                    }
                }
                this.digestId = 0;
            } catch (OCKException e) {
                e.printStackTrace();
            }
        }
    }

    

    // Size of {SHA256, SHA384, SHA512, SHA224, SHA1}
    final static int[] digestLengths = {32, 48, 64, 28, 20};

    //disable caching mechanism for windows OS
    final static private boolean isWindows = System.getProperty("os.name").startsWith("Windows");

    final static private int numContexts;

    final static int numShaAlgos = 5;
    private static final String DIGEST_CONTEXT_CACHE_SIZE = "com.ibm.crypto.provider.DigestContextCacheSize";

    private static boolean needsInit = true;

    static private ConcurrentLinkedQueueLong contexts[];

    static private int runtimeContextNum[];

    class ConcurrentLinkedQueueLong extends ConcurrentLinkedQueue<Long> {
        private static final long serialVersionUID = 196745693267521676L;
    }

    static {
        // Configurable number of cached contexts
        int tmpNumContext = 0;
        if (isWindows) {
            tmpNumContext = 0;
        } else {
            try {
                tmpNumContext = Integer
                        .parseInt(System.getProperty(DIGEST_CONTEXT_CACHE_SIZE, "2048"));
            } catch (NumberFormatException e) {
                tmpNumContext = 0;
            }
        }
        numContexts = tmpNumContext;
    }

    void getContext() throws OCKException {
        if (needsInit) {
            synchronized (Digest.class) {
                if (needsInit) {
                    contexts = new ConcurrentLinkedQueueLong[numShaAlgos];
                    runtimeContextNum = new int[numShaAlgos];

                    for (int i = 0; i < numShaAlgos; i++) {
                        contexts[i] = new ConcurrentLinkedQueueLong();
                        runtimeContextNum[i] = 0;
                    }
                    needsInit = false;
                }
            }
        }

        if (this.resources.digestId != 0) {
            return;
        }

        if (this.resources.algIndx == -1) {
            switch (this.digestAlgo) {
                case "SHA256":
                    this.resources.algIndx = 0;
                    break;
                case "SHA384":
                    this.resources.algIndx = 1;
                    break;
                case "SHA512":
                    this.resources.algIndx = 2;
                    break;
                case "SHA224":
                    this.resources.algIndx = 3;
                    break;
                case "SHA1":
                    this.resources.algIndx = 4;
                    break;
                default:
                    this.resources.algIndx = -2;
                    break;
            }
        }

        // Algorithm is not SHA*
        if (this.resources.algIndx == -2) {
            this.resources.digestId = NativeInterface.DIGEST_create(this.resources.ockContext.getId(),
                    this.digestAlgo);
        } else {
            Long context = contexts[this.resources.algIndx].poll();

            if (context == null) {
                // Create new context
                this.resources.digestId = NativeInterface
                        .DIGEST_create(this.resources.ockContext.getId(), this.digestAlgo);
                this.resources.contextFromQueue = (runtimeContextNum[this.resources.algIndx] < numContexts);
                if (runtimeContextNum[this.resources.algIndx] < numContexts) {
                    runtimeContextNum[this.resources.algIndx]++;
                }
            } else {
                this.resources.digestId = context;
                this.resources.contextFromQueue = true;
            }
        }
        this.resources.needsReinit = false;
    }

    /* end digest caching mechanism
     * ===========================================================================
     */

    private Resources resources;
    private int digestLength = 0;
    private final String badIdMsg = "Digest Identifier is not valid";
    private static final String debPrefix = "DIGEST";

    private String digestAlgo;

    

    public static Digest getInstance(OCKContext ockContext, String digestAlgo) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (digestAlgo == null || digestAlgo.isEmpty()) {
            throw new IllegalArgumentException("digestAlgo is null/empty");
        }

        return new Digest(ockContext, digestAlgo);
    }

    private Digest(OCKContext ockContext, String digestAlgo) throws OCKException {
        //final String methodName = "Digest(String)";
        this.resources = new Resources();

        this.resources.ockContext = ockContext;
        this.digestAlgo = digestAlgo;
        getContext();
        //OCKDebug.Msg(debPrefix, methodName,  "digestAlgo :" + digestAlgo);

        OpenJCEPlusProvider.registerCleanableC(this, cleanOCKResources(digestId, algIndx,
                contextFromQueue, needsReinit, ockContext));
    }

    static void throwOCKException(int errorCode) throws OCKException {
        //final String methodName = "throwOCKExeption";
        // OCKDebug.Msg(debPrefix, methodName, "throwOCKException errorCode =  " + errorCode);
        switch (errorCode) {
            case -1:
                throw new OCKException("ICC_EVP_DigestFinal failed!");
            case -2:
                throw new OCKException("ICC_EVP_DigestInit failed!");
            case -3:
                throw new OCKException("ICC_EVP_DigestUpdate failed!");
            default:
                throw new OCKException("Unknow Error Code");
        }
    }

    public synchronized void update(byte[] input, int offset, int length) throws OCKException {
        //final String methodName = "update ";
        int errorCode = 0;

        if (length == 0) {
            return;
        }

        if (input == null || length < 0 || offset < 0 || (offset + length) > input.length) {
            throw new IllegalArgumentException("Input range is invalid.");
        }

        //OCKDebug.Msg(debPrefix, methodName, "offset :"  + offset + " digestId :" + this.digestId + " length :" + length);
        if (!validId(this.resources.digestId)) {
            throw new OCKException(badIdMsg);
        }

        errorCode = NativeInterface.DIGEST_update(this.resources.ockContext.getId(),
                this.resources.digestId, input, offset, length);
        if (errorCode < 0) {
            throwOCKException(errorCode);
        }
        this.resources.needsReinit = true;
    }

    public synchronized byte[] digest() throws OCKException {
        //final String methodName = "digest()";
        int errorCode = 0;

        if (!validId(this.resources.digestId)) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg (debPrefix, methodName, "digestId :" + this.digestId);


        // push data from the buffer that haven't got updated yet
        int digestLength = getDigestLength();
        byte[] digestBytes = new byte[digestLength];

        errorCode = NativeInterface.DIGEST_digest_and_reset(this.resources.ockContext.getId(),
                this.resources.digestId, digestBytes);
        if (errorCode < 0) {
            throwOCKException(errorCode);
        }
        this.resources.needsReinit = false;

        return digestBytes;
    }

    protected long getId() throws OCKException {
        //final String methodName = "getId()";
        //OCKDebug.Msg(debPrefix, methodName, "digestId :" + this.digestId);
        return this.resources.digestId;
    }

    public int getDigestLength() throws OCKException {
        //final String methodName = "getDigestLength()";

        if (digestLength == 0) {
            obtainDigestLength();
        }
        //OCKDebug.Msg(debPrefix, methodName, "digestLength :" + digestLength);
        return digestLength;
    }

    private synchronized void obtainDigestLength() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getDigestLength at the same time, we only want to call the
        // native code one time.

        // if SHA* algorithms
        if (this.resources.algIndx >= 0 && this.resources.algIndx < numShaAlgos) {
            this.digestLength = digestLengths[this.resources.algIndx];
        } else {
            if (this.digestLength == 0) {
                if (!validId(this.resources.digestId)) {
                    throw new OCKException(badIdMsg);
                }
                this.digestLength = NativeInterface.DIGEST_size(this.resources.ockContext.getId(),
                        this.resources.digestId);
            }
        }
    }

    @Override
    public void cleanup() {
        //final String methodName = "finalize";

        //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);
        try {
            releaseContext();
        } catch (OCKException e) {
            e.printStackTrace();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg(debPrefix, methodName,  "Id : " + id);
        return (id != 0L);
    }

    /**
     * Clones a given Digest.
     */
    public synchronized Object clone() throws CloneNotSupportedException {
        // Create new Digest instance and copy all relevant fields into the copy.
        // Clones do not make use of the cache so always set the value of
        // contextFromQueue to false to ensure that the context is later freed
        // correctly.
        Digest copy = new Digest();
        copy.digestLength = this.digestLength;
        copy.resources = new Resources();
        copy.resources.algIndx = this.resources.algIndx;
        copy.digestAlgo = new String(this.digestAlgo);
        copy.resources.needsReinit = this.resources.needsReinit;
        copy.resources.ockContext = this.resources.ockContext;
        copy.resources.contextFromQueue = false;

        // Allocate a new context for the digestId and copy all state information from our
        // original context into the copy.
        try {
            copy.resources.digestId = NativeInterface.DIGEST_copy(
                this.resources.ockContext.getId(), getId());
            if (copy.resources.digestId == 0) {
                throw new CloneNotSupportedException("Copy of native digest context failed.");
            }
        } catch (OCKException e) {
            StackTraceElement[] stackTraceArray = e.getStackTrace();
            String stackTrace = Stream.of(stackTraceArray)
                                      .map(t -> t.toString())
                                      .collect(Collectors.joining("\n"));
            throw new CloneNotSupportedException(stackTrace);
        }

        OpenJCEPlusProvider.registerCleanableC(copy, cleanOCKResources(copy.digestId, copy.algIndx,
                copy.contextFromQueue, copy.needsReinit, copy.ockContext));
        return copy;
    }

    private static Runnable cleanOCKResources(long digestId, int algIndx, boolean contextFromQueue,
            boolean needsReinit, OCKContext ockContext) {
        return () -> {
            try {
                if (digestId == 0) {
                    throw new OCKException("Digest Identifier is not valid");
                }

                // not SHA* algorithm
                if (algIndx == -2) {
                    if (validId(digestId)) {
                        NativeInterface.DIGEST_delete(ockContext.getId(), digestId);
                    }
                } else {
                    if (contextFromQueue) {
                        // reset now to make sure all contexts in the queue are ready to use
                        if (needsReinit) {
                            NativeInterface.DIGEST_reset(ockContext.getId(), digestId);
                        }
                        
                        Digest.contexts[algIndx].add(digestId);
                    } else {
                        // delete context
                        NativeInterface.DIGEST_delete(ockContext.getId(), digestId);
                    }
                }
            } catch (OCKException e) {
                e.printStackTrace();
            }
            
        };
    }
}
