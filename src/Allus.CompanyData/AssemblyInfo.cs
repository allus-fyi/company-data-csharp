using System.Runtime.CompilerServices;

// Expose internal helpers (e.g. Client.DecryptValueForTest, AtomicWrite) to the test assembly only.
[assembly: InternalsVisibleTo("Allus.CompanyData.Tests")]
