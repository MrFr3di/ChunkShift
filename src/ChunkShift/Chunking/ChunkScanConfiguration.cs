using ChunkShift.Primitives;

namespace ChunkShift.Chunking;

internal static class ChunkScanConfiguration
{
    // Core 0.1.0 registers exactly one stable chunking profile. Nested static
    // initialization computes its fingerprint once while keeping steady-state
    // explicit/default resolution allocation-free.

    internal static ChunkingKernelProfile ResolveProfile(ChunkingProfileId? requested) =>
        ResolveProfileRegistration(requested).KernelProfile;

    // Chunking needs the exact semantics, so an unknown profile cannot run and
    // is NotSupported. A null request selects the stable Core default.
    internal static ProfileRegistration ResolveProfileRegistration(
        ChunkingProfileId? requested)
    {
        if (requested is null)
        {
            return Stable64K.Value;
        }

        if (TryResolveProfileRegistration(requested, out ProfileRegistration registration))
        {
            return registration;
        }

        throw new NotSupportedException($"Unsupported ChunkingProfileId '{requested}'.");
    }

    // Manifest-only verification never runs the chunker: an unknown ProfileId is
    // not an error there, while a known one lets the caller check the recorded
    // ProfileFingerprint against this build's semantics.
    internal static bool TryResolveProfileRegistration(
        ChunkingProfileId profileId,
        out ProfileRegistration registration)
    {
        if (profileId == Stable64K.Value.Id)
        {
            registration = Stable64K.Value;
            return true;
        }

        registration = default;
        return false;
    }

    // Returns the canonical instance, so later suite dispatch compares by
    // reference before falling back to an ordinal string comparison.
    internal static HashSuiteId ResolveHashSuite(HashSuiteId? requested)
    {
        if (requested is null)
        {
            return HashSuiteIds.Default;
        }

        if (requested == HashSuiteIds.Blake3256V1)
        {
            return HashSuiteIds.Blake3256V1;
        }

        if (requested == HashSuiteIds.Sha256V1)
        {
            return HashSuiteIds.Sha256V1;
        }

        throw new NotSupportedException($"Unsupported HashSuiteId '{requested}'.");
    }

    private static class Stable64K
    {
        internal static readonly ProfileRegistration Value =
            ProfileRegistration.Create(
                FastCdcProfile.Stable64KProfileId,
                FastCdcProfile.CreateStable64K());
    }

    internal readonly struct ProfileRegistration
    {
        private ProfileRegistration(
            ChunkingProfileId id,
            ProfileFingerprint fingerprint,
            ChunkingKernelProfile kernelProfile)
        {
            Id = id;
            Fingerprint = fingerprint;
            KernelProfile = kernelProfile;
        }

        internal ChunkingProfileId Id { get; }

        internal ProfileFingerprint Fingerprint { get; }

        internal ChunkingKernelProfile KernelProfile { get; }

        internal static ProfileRegistration Create(
            ChunkingProfileId id,
            FastCdcProfile profile)
        {
            // The fingerprint is computed once during type initialization.
            // Profile resolution is on every explicit scan and must remain
            // allocation-free.
            ProfileFingerprint fingerprint = profile.ComputeFingerprint();
            return new ProfileRegistration(
                id,
                fingerprint,
                ChunkingKernelProfile.FastCdcGear(profile));
        }
    }
}
