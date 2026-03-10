package io.parquet.security;

import java.util.Objects;

/**
 * Result from policy provider containing permitted bitmap mask.
 * Represents which security dimensions the user is allowed to access.
 */
public class PermittedMask {
    public final long permittedLo;
    public final long permittedHi;

    public PermittedMask(long permittedLo, long permittedHi) {
        this.permittedLo = permittedLo;
        this.permittedHi = permittedHi;
    }

    /**
     * Check if a row with given security bitmap is permitted.
     *
     * @param secLo Row's _sec_lo value
     * @param secHi Row's _sec_hi value
     * @return true if row is permitted, false otherwise
     */
    public boolean isPermitted(long secLo, long secHi) {
        // Compute forbidden masks
        long forbiddenLo = (~permittedLo) & 0x7FFF_FFFF_FFFF_FFFFL;
        long forbiddenHi = (~permittedHi) & 0x7FFF_FFFF_FFFF_FFFFL;

        // Row is permitted if it has no forbidden bits set
        return ((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0);
    }

    /**
     * Convenience method for version-aware filtering.
     * Extracts version from secLo (bits 60-63) and cleans characterization bits.
     *
     * @param secLo Row's _sec_lo value
     * @param secHi Row's _sec_hi value
     * @return true if row is permitted, false otherwise
     */
    public boolean isPermittedWithVersion(long secLo, long secHi) {
        // Extract version (bits 60-63)
        int version = (int)((secLo >> 60) & 0xF);

        // Clean characterization bits (mask out version bits)
        long secLoClean = secLo & 0x0FFF_FFFF_FFFF_FFFFL;

        return isPermitted(secLoClean, secHi);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PermittedMask that = (PermittedMask) o;
        return permittedLo == that.permittedLo && permittedHi == that.permittedHi;
    }

    @Override
    public int hashCode() {
        return Objects.hash(permittedLo, permittedHi);
    }

    @Override
    public String toString() {
        return "PermittedMask{" +
               "permittedLo=0x" + Long.toHexString(permittedLo) +
               ", permittedHi=0x" + Long.toHexString(permittedHi) +
               '}';
    }
}
