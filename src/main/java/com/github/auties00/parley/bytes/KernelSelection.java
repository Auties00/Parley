package com.github.auties00.parley.bytes;

import java.lang.System.Logger.Level;

/// Chooses the [ByteKernels] of the process on first use.
final class KernelSelection {
    /// The chosen kernels.
    static final ByteKernels INSTANCE = select();

    private KernelSelection() {
        throw new AssertionError("KernelSelection cannot be instantiated");
    }

    /// {@return the vectorized kernels when they can run and are not disabled, the scalar ones otherwise}
    private static ByteKernels select() {
        if ("false".equalsIgnoreCase(System.getProperty(ByteKernels.VECTOR_PROPERTY))) {
            return ScalarByteKernels.INSTANCE;
        }
        // Checked first so that VectorByteKernels, which links against the Vector API, is never loaded without it
        if (ModuleLayer.boot().findModule("jdk.incubator.vector").isEmpty()) {
            return ScalarByteKernels.INSTANCE;
        }
        try {
            var kernels = VectorByteKernels.create();
            return kernels == null ? ScalarByteKernels.INSTANCE : kernels;
        } catch (LinkageError | RuntimeException exception) {
            var logger = System.getLogger(ByteKernels.class.getName());
            if (logger.isLoggable(Level.DEBUG)) {
                logger.log(Level.DEBUG, "the vectorized byte kernels are unavailable", exception);
            }
            return ScalarByteKernels.INSTANCE;
        }
    }
}
