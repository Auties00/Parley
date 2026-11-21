/// Provides the byte kernels of the packet paths: XOR of forward error correction parity and the search for H.264
/// and H.265 start codes, each with a vectorized implementation on the incubating Vector API and a scalar one.
///
/// [ByteKernels#get()] chooses once per process. The vectorized kernels run when the `jdk.incubator.vector` module
/// is in the boot layer (`--add-modules jdk.incubator.vector`), its preferred species is wider than 64 bits, and the
/// {@systemProperty parley.vector} system property is not `false`; otherwise, and always when the module is absent,
/// the scalar kernels run. Both produce identical results.
///
/// The package is internal to Parley and the module does not export it.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
package com.github.auties00.parley.bytes;
