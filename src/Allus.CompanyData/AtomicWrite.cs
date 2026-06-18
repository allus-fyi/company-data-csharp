// Crash-safe atomic file writes (the durability discipline).
//
// Every durable write — the changes-pump buffer files, the seq counter, BinaryHandle.SaveAsync —
// goes through here so a crash mid-write never leaves a half-written / truncated file: write to a
// temp file in the SAME directory, flush to disk (FileStream.Flush(flushToDisk: true) — fsync),
// then atomically File.Move(temp, dest, overwrite: true) over any existing file. The destination
// is therefore always either the old complete file or the new complete one.

using System.Text;

namespace Allus.CompanyData;

internal static class AtomicWrite
{
    /// <summary>Atomically write <paramref name="data"/> to <paramref name="path"/> (temp+flush+move).</summary>
    public static void WriteBytes(string path, byte[] data)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (string.IsNullOrEmpty(directory)) directory = ".";
        var tmp = Path.Combine(directory, ".tmp_" + Guid.NewGuid().ToString("N") + ".part");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(data, 0, data.Length);
                fs.Flush(flushToDisk: true); // fsync the data + metadata before the move
            }
            File.Move(tmp, path, overwrite: true); // atomic rename over any existing file
        }
        catch
        {
            // Clean up the temp file on any failure so we never leak partials.
            TryDelete(tmp);
            throw;
        }
    }

    /// <summary>Atomically write <paramref name="text"/> as UTF-8 to <paramref name="path"/>.</summary>
    public static void WriteText(string path, string text)
        => WriteBytes(path, Encoding.UTF8.GetBytes(text));

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best-effort cleanup */ }
        catch (UnauthorizedAccessException) { /* best-effort cleanup */ }
    }
}
