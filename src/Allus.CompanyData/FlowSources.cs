// A document leaf's participant PDF sources and the generation inputs they need.
//
// A leaf output rule's PDF is a company template (asset_key), a flow field's answer
// (source_field: slug → source key "field:<slug>") or what a bound customer shared on its
// connection (source_connection: {party, request_slug} → "conn:<party>:<request_slug>"). The
// generating party uploads its own copy of every HELD source of the run's current leaf, sealed under
// the call's one-time key, before it calls /generate; the server refuses a generate whose inputs are
// not exactly the held set.

using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>
/// One held participant source of the current leaf. <see cref="Kind"/> is <c>field</c>
/// (<see cref="Slug"/> the flow field, <see cref="File"/> the generating party's own answer file) or
/// <c>conn</c> (<see cref="File"/> the generating party's own copy made at run start).
/// </summary>
internal sealed record HeldSource(string SourceKey, string Kind, string? Slug, string File);

internal static class FlowSources
{
    /// <summary>
    /// The file a plaintext <c>{"_enc_file": file, …}</c> answer value names, else null. A captured,
    /// uploaded or frozen-linked file answer is that plaintext reference, never a ciphertext
    /// wrapper; every other answer value is a wrapper and answers null.
    /// </summary>
    internal static string? FileRef(Node value)
    {
        var obj = value;
        if (value.Kind == NodeKind.Scalar && value.RawScalar is string json)
        {
            try { obj = Node.FromJsonString(json); }
            catch (JsonException) { return null; }
        }
        return obj.Kind == NodeKind.Object && obj.Get("_enc_file").RawScalar is string f && f.Length > 0
            ? f
            : null;
    }

    /// <summary>A file-reference answer value as the marker string it stands in the answer map as.</summary>
    internal static string FileRefMarker(Node value) =>
        value.Kind == NodeKind.Scalar && value.RawScalar is string s ? s : value.ToJsonString();

    /// <summary>
    /// The held set of the leaf <paramref name="nodeKey"/>, in rule order, each source key once.
    /// Reads every rule of every output of the leaf (a leaf with the older <c>pdfs</c> list carries
    /// template rules only). <c>field:&lt;slug&gt;</c> is held when the generating party's own answer
    /// copy for the slug (<c>for_user_id == ownUserId</c>) is a file reference;
    /// <c>conn:&lt;party&gt;:&lt;slug&gt;</c> when <paramref name="sourceFiles"/> (the run read's own
    /// copies) names it.
    /// </summary>
    internal static List<HeldSource> Held(
        Node definition, string? nodeKey, IReadOnlyList<Node> answers, string? ownUserId,
        IReadOnlyDictionary<string, string> sourceFiles)
    {
        var outList = new List<HeldSource>();
        var node = definition.Get("nodes").AsList()
            .FirstOrDefault(n => n.Kind == NodeKind.Object && n.Get("key").AsString() == nodeKey);
        if (node is null || node.Get("outputs").Kind != NodeKind.List) return outList;
        var ownFiles = new Dictionary<string, string>();
        foreach (var row in answers)
        {
            if (ownUserId is null || row.Get("for_user_id").AsString() != ownUserId) continue;
            var slug = row.Get("slug").AsString();
            var f = FileRef(row.Get("value"));
            if (!string.IsNullOrEmpty(slug) && f is not null) ownFiles[slug!] = f;
        }
        var seen = new HashSet<string>();
        foreach (var output in node.Get("outputs").AsList())
        {
            foreach (var rule in output.Get("rules").AsList())
            {
                if (rule.Kind != NodeKind.Object) continue;
                var conn = rule.Get("source_connection");
                if (rule.Get("source_field").RawScalar is string field && field.Length > 0)
                {
                    var key = $"field:{field}";
                    if (ownFiles.TryGetValue(field, out var f) && seen.Add(key))
                        outList.Add(new HeldSource(key, "field", field, f));
                }
                else if (conn.Kind == NodeKind.Object
                    && conn.Get("party").RawScalar is string party
                    && conn.Get("request_slug").RawScalar is string requestSlug)
                {
                    var key = $"conn:{party}:{requestSlug}";
                    if (sourceFiles.TryGetValue(key, out var f) && !string.IsNullOrEmpty(f) && seen.Add(key))
                        outList.Add(new HeldSource(key, "conn", null, f));
                }
            }
        }
        return outList;
    }

    /// <summary>
    /// Upload each held source, then POST <paramref name="generatePath"/> with
    /// <c>{otk, values, inputs}</c>. <paramref name="envelopeOf"/> fetches and decrypts the generating
    /// party's own copy of one source to its envelope JSON string. Each envelope is sealed under the
    /// SAME one-time key as <c>values</c> and POSTed to <c>{generatePath}/inputs</c> as
    /// <c>{source_key, value}</c> → <c>{input}</c>; <c>inputs</c> is <c>[]</c> when nothing is held.
    /// </summary>
    internal static async Task<Node> GenerateWithInputsAsync(
        ApiHttp http, string generatePath, IReadOnlyDictionary<string, object?> answers,
        IReadOnlyList<HeldSource> held, Func<HeldSource, CancellationToken, Task<string>> envelopeOf,
        CancellationToken ct)
    {
        var otk = Crypto.NewOneTimeKey();
        var inputs = new List<object?>();
        foreach (var src in held)
        {
            var envelope = await envelopeOf(src, ct).ConfigureAwait(false);
            var res = await http.PostAsync($"{generatePath}/inputs", jsonBody: new Dictionary<string, object?>
            {
                ["source_key"] = src.SourceKey,
                ["value"] = Crypto.OneTimeKeySeal(otk, envelope),
            }, ct: ct).ConfigureAwait(false);
            if (res.Get("input").RawScalar is not string ident || ident.Length == 0)
                throw new ApiException(0, null, $"generate/inputs answered no input for {src.SourceKey}");
            inputs.Add(new Dictionary<string, object?> { ["source_key"] = src.SourceKey, ["input"] = ident });
        }
        var body = Crypto.OneTimeKeyBundle(answers, otk);
        body["inputs"] = inputs;
        return await http.PostAsync(generatePath, jsonBody: body, ct: ct).ConfigureAwait(false);
    }

    /// <summary>A sealed wrapper as the JSON string an upload body carries.</summary>
    internal static string SealedString(object sealedValue) => sealedValue switch
    {
        string s => s,
        Node n => n.ToJsonString(),
        _ => JsonSerializer.Serialize(sealedValue),
    };

    /// <summary>The <c>file</c> of an upload's <c>201 {file}</c> response.</summary>
    internal static string ResponseFile(Node body) =>
        body.Get("file").RawScalar is string f && f.Length > 0
            ? f
            : throw new ApiException(0, null, "the upload response carried no file");
}
