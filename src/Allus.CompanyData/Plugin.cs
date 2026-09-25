// Plugins on contract flows, request fields and sign-in consent.
//
// A plugin field is answered by picking from lists a plugin serves and reading the outputs it
// computes. Its stored answer is self-describing JSON:
//
//   {"plugin":"Flex","type":"cao",
//    "blocks":[{"key":"cao","kind":"search_select","label":"CAO","id":"hrc","value":"Horeca Fictief"},…],
//    "outputs":[{"key":"min_wage","type":"number","label":"Minimum wage","value":9.5},…]}
//
// This file holds the typed model of that answer (PluginValue) and the helpers a company party of a
// flow uses to call a plugin: a pass from the API, the request sealed to the plugin's public key and
// posted to the forwarder over a plain transport that carries no allme credential, and the reply
// opened with a key pair made for the call.

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Allus.CompanyData;

/// <summary>
/// One answered block of a plugin answer: a search_select pick carries its <see cref="Id"/> and its
/// option label as <see cref="Value"/>; a text, number or date block its typed value and a null id.
/// </summary>
public sealed record PluginBlock(string? Key, string? Kind, string? Label, string? Id, object? Value);

/// <summary>
/// One output of a plugin answer, of its declared <see cref="Type"/> (text, number, date or boolean);
/// <see cref="Value"/> is null when the plugin had no value for it.
/// </summary>
public sealed record PluginOutput(string? Key, string? Type, string? Label, object? Value);

/// <summary>
/// A plugin answer: the plugin's name, the field type answered, the blocks in declared order and the
/// outputs. An answer without an outputs array is unfinished and is not a PluginValue.
/// </summary>
public sealed record PluginValue(
    string? Plugin, string? Type, IReadOnlyList<PluginBlock> Blocks, IReadOnlyList<PluginOutput> Outputs)
{
    /// <summary>The reserved field-type key of a plugin row. It is never a registry row, so every reader branches on it first.</summary>
    public const string TypeKey = "plugin";

    /// <summary>The parsed answer object (escape hatch).</summary>
    public object? Raw { get; init; }

    /// <summary>
    /// Parse the plaintext of a plugin answer — a company-data value of a plugin row, a flow answer of a
    /// plugin element, or a sign-in claim value of a plugin claim. A plaintext that is not a JSON object
    /// with an <c>outputs</c> array (an unfinished answer has none) throws
    /// <see cref="ValidationException"/> with field type <c>plugin</c>.
    /// </summary>
    public static PluginValue Parse(string plaintext)
    {
        Node obj;
        try { obj = Node.FromJsonString(plaintext); }
        catch (JsonException) { throw new ValidationException("", TypeKey); }
        if (obj.Kind != NodeKind.Object || obj.Get("outputs").Kind != NodeKind.List)
            throw new ValidationException("", TypeKey);
        var blocks = obj.Get("blocks").AsList()
            .Where(b => b.Kind == NodeKind.Object)
            .Select(b => new PluginBlock(
                b.Get("key").AsString(),
                b.Get("kind").AsString(),
                b.Get("label").AsString(),
                b.Get("id").IsNull ? null : FlowCondition.StringOf(b.Get("id").ToObjectGraph()),
                b.Get("value").ToObjectGraph()))
            .ToList();
        var outputs = obj.Get("outputs").AsList()
            .Where(o => o.Kind == NodeKind.Object)
            .Select(o => new PluginOutput(
                o.Get("key").AsString(), o.Get("type").AsString(), o.Get("label").AsString(), o.Get("value").ToObjectGraph()))
            .ToList();
        return new PluginValue(obj.Get("plugin").AsString(), obj.Get("type").AsString(), blocks, outputs)
        {
            Raw = obj.ToObjectGraph(),
        };
    }
}

/// <summary>One plugin a pass unlocks. <see cref="PublicKey"/> is null when the plugin's description is missing or failed; such a plugin is not responding.</summary>
public sealed record PluginPassPlugin(string? Id, string? PublicKey);

/// <summary>
/// A short-lived pass for the forwarder, the forwarder's address, the plugins it unlocks and the
/// plugin description (plugin_spec) of every plugin element it covers, keyed by the element's slug.
/// </summary>
public sealed record PluginPass(
    string? Pass, string ForwarderUrl, IReadOnlyList<PluginPassPlugin> Plugins, IReadOnlyDictionary<string, Node> Specs)
{
    /// <summary>The underlying API object (escape hatch).</summary>
    public object? Raw { get; init; }

    internal static PluginPass FromApi(Node obj)
    {
        var plugins = obj.Get("plugins").AsList()
            .Where(p => p.Kind == NodeKind.Object)
            .Select(p => new PluginPassPlugin(p.Get("id").AsString(), p.Get("public_key").AsString()))
            .ToList();
        var specs = new Dictionary<string, Node>();
        foreach (var (slug, spec) in obj.Get("specs").AsObject())
            if (spec.Kind == NodeKind.Object) specs[slug] = spec;
        return new PluginPass(
            obj.Get("pass").AsString(),
            (obj.Get("forwarder_url").AsString() ?? "").TrimEnd('/'),
            plugins,
            specs)
        { Raw = obj.ToObjectGraph() };
    }

    internal string? PublicKeyFor(string? pluginId) => Plugins.FirstOrDefault(p => p.Id == pluginId)?.PublicKey;
}

/// <summary>One option a plugin serves for a search_select block.</summary>
public sealed record PluginOption(string Id, string Label);

/// <summary>A plugin's option list; <see cref="More"/> says the list was cut (at most 50 options) and a longer query narrows it.</summary>
public sealed record PluginOptionsResult(IReadOnlyList<PluginOption> Options, bool More);

/// <summary>What <c>PluginOutputsAsync</c> answers: <see cref="PluginOutputs"/> or <see cref="PluginPicksInvalid"/>.</summary>
public abstract record PluginOutputsResult;

/// <summary>The outputs a plugin computed, by output key (a null value means the plugin had none).</summary>
public sealed record PluginOutputs(IReadOnlyDictionary<string, object?> Outputs) : PluginOutputsResult;

/// <summary>The picks no longer fit the current inputs or each other: clear them and pick again.</summary>
public sealed record PluginPicksInvalid : PluginOutputsResult;

/// <summary>
/// What the service Client and the CustomerClient supply to the shared plugin call: how to read the
/// run, how to get a pass, which answers the caller can read, and which user id is its own.
/// </summary>
internal sealed class PluginFlowParty
{
    /// <summary>
    /// The plain transport the forwarder is reached over: its own HttpClient with no bearer token or
    /// other allme credential, no base-URL rewriting and no redirect followed. The forwarder gives a
    /// plugin 3 s, plus 1 s for a manifest refetch on a key change.
    /// </summary>
    internal static HttpClient NewTransport() =>
        new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };

    private readonly HttpClient _transport;
    private readonly Func<CancellationToken, Task<FlowRun>> _fetchRun;
    private readonly Func<CancellationToken, Task<PluginPass>> _fetchPass;
    private readonly Func<FlowRun, Dictionary<string, object?>> _storedAnswers;
    private readonly Func<FlowRun, string?> _ownUserId;

    internal PluginFlowParty(
        HttpClient transport,
        Func<CancellationToken, Task<FlowRun>> fetchRun,
        Func<CancellationToken, Task<PluginPass>> fetchPass,
        Func<FlowRun, Dictionary<string, object?>> storedAnswers,
        Func<FlowRun, string?> ownUserId)
    {
        _transport = transport;
        _fetchRun = fetchRun;
        _fetchPass = fetchPass;
        _storedAnswers = storedAnswers;
        _ownUserId = ownUserId;
    }

    internal async Task<PluginOptionsResult> OptionsAsync(
        string slug, string block, string query,
        IReadOnlyDictionary<string, string>? picks, IReadOnlyDictionary<string, object?>? values,
        IReadOnlyDictionary<string, object?>? draft, CancellationToken ct)
    {
        var reply = await CallAsync(slug, draft, (fieldType, inputs) => new Dictionary<string, object?>
        {
            ["field_type"] = fieldType,
            ["op"] = "options",
            ["block"] = block,
            ["query"] = query,
            ["picks"] = picks ?? new Dictionary<string, string>(),
            ["values"] = values ?? new Dictionary<string, object?>(),
            ["inputs"] = inputs,
        }, ct).ConfigureAwait(false);
        if (reply.Get("options").Kind != NodeKind.List)
            throw new ApiException(0, "plugin.not_responding", "the plugin reply carries no options");
        var options = reply.Get("options").AsList()
            .Where(o => o.Kind == NodeKind.Object)
            .Select(o => new PluginOption(
                FlowCondition.StringOf(o.Get("id").ToObjectGraph()), FlowCondition.StringOf(o.Get("label").ToObjectGraph())))
            .ToList();
        return new PluginOptionsResult(options, ModelCoerce.CoerceBool(reply.Get("more")) ?? false);
    }

    internal async Task<PluginOutputsResult> OutputsAsync(
        string slug, IReadOnlyDictionary<string, string>? picks, IReadOnlyDictionary<string, object?>? values,
        IReadOnlyDictionary<string, object?>? draft, CancellationToken ct)
    {
        var reply = await CallAsync(slug, draft, (fieldType, inputs) => new Dictionary<string, object?>
        {
            ["field_type"] = fieldType,
            ["op"] = "outputs",
            ["picks"] = picks ?? new Dictionary<string, string>(),
            ["values"] = values ?? new Dictionary<string, object?>(),
            ["inputs"] = inputs,
        }, ct).ConfigureAwait(false);
        if (ModelCoerce.CoerceBool(reply.Get("picks_invalid")) == true) return new PluginPicksInvalid();
        if (reply.Get("outputs").ToObjectGraph() is not IReadOnlyDictionary<string, object?> outputs)
            throw new ApiException(0, "plugin.not_responding", "the plugin reply carries no outputs");
        return new PluginOutputs(outputs);
    }

    // Resolve the element's inputs from the one live answer map, seal the request to the plugin's
    // key, post it to the forwarder and open the reply. A 409 plugin.key_changed reseals once with
    // the key it names; a 401 or 403 takes a new pass once.
    private async Task<Node> CallAsync(
        string slug, IReadOnlyDictionary<string, object?>? draft,
        Func<string?, Dictionary<string, object?>, Dictionary<string, object?>> build, CancellationToken ct)
    {
        var run = await _fetchRun(ct).ConfigureAwait(false);
        var stored = _storedAnswers(run);
        var live = LiveAnswers(run, stored, draft);
        var pass = await _fetchPass(ct).ConfigureAwait(false);
        if (!pass.Specs.TryGetValue(slug, out var spec))
            throw new ConfigException($"\"{slug}\" is not a plugin field on the run's current step");
        var privacy = new FlowPrivacy(run, draft, _ownUserId(run));
        var inputs = Inputs(spec, live, privacy);
        var pluginId = spec.Get("plugin_id").AsString();
        var request = build(spec.Get("field_type").AsString(), inputs);

        var spki = pass.PublicKeyFor(pluginId);
        bool resealed = false, renewed = false;
        while (true)
        {
            if (string.IsNullOrEmpty(spki))
                throw new ApiException(0, "plugin.not_responding", "the plugin has no usable description");
            using var pluginKey = Crypto.LoadPublicKey(spki);
            var (status, body, replyKey) = await PostAsync(pass, pluginId, pluginKey, request, ct).ConfigureAwait(false);
            using (replyKey)
            {
                var errorKey = body.Get("error_key").AsString();
                if (status == HttpStatusCode.OK)
                {
                    var reply = Crypto.Decrypt(body.Get("reply"), replyKey);
                    Node parsed;
                    try { parsed = Node.FromJsonString(reply); }
                    catch (JsonException ex) { throw new ApiException(0, "plugin.not_responding", $"the plugin reply is not a JSON object: {ex.Message}"); }
                    if (parsed.Kind != NodeKind.Object)
                        throw new ApiException(0, "plugin.not_responding", "the plugin reply is not a JSON object");
                    return parsed;
                }
                if (status == HttpStatusCode.Conflict && errorKey == "plugin.key_changed" && !resealed)
                {
                    resealed = true;
                    spki = body.Get("public_key").AsString();
                    continue;
                }
                if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden && !renewed)
                {
                    renewed = true;
                    pass = await _fetchPass(ct).ConfigureAwait(false);
                    spki = pass.PublicKeyFor(pluginId);
                    continue;
                }
                throw new ApiException((int)status, errorKey, body.Get("error").AsString());
            }
        }
    }

    // Seal the request with a reply key made for this attempt and post {pass, plugin_id, request}.
    private async Task<(HttpStatusCode Status, Node Body, RSA ReplyKey)> PostAsync(
        PluginPass pass, string? pluginId, RSA pluginKey, Dictionary<string, object?> request, CancellationToken ct)
    {
        var (replyKey, replySpki) = Crypto.GenerateReplyKey();
        try
        {
            request["reply_key"] = replySpki;
            var sealedRequest = Crypto.EncryptForPublicKey(JsonSerializer.Serialize(request), pluginKey);
            var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["pass"] = pass.Pass,
                ["plugin_id"] = pluginId,
                ["request"] = sealedRequest.ToJsonString(),
            });
            using var message = new HttpRequestMessage(HttpMethod.Post, pass.ForwarderUrl + "/call")
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            };
            message.Headers.Accept.ParseAdd("application/json");
            HttpResponseMessage response;
            try
            {
                response = await _transport.SendAsync(message, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                throw new ApiException(0, "plugin.not_responding", $"the forwarder could not be reached: {ex.Message}");
            }
            using (response)
            {
                var raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                Node body;
                try { body = raw.Length == 0 ? Node.Null : Node.FromJsonString(raw); }
                catch (JsonException) { body = Node.Null; }
                return (response.StatusCode, body, replyKey);
            }
        }
        catch
        {
            replyKey.Dispose();
            throw;
        }
    }

    // ── the live answer map, privacy and inputs ──────────────────────────────────────────────

    /// <summary>The slugs of every plugin element in a flow definition.</summary>
    internal static List<string> PluginSlugsOf(Node definition)
    {
        var slugs = new List<string>();
        foreach (var (_, el) in Elements(definition))
            if (el.Get("kind").AsString() == "plugin" && el.Get("slug").AsString() is { Length: > 0 } s) slugs.Add(s);
        return slugs;
    }

    private static IEnumerable<(string? NodeKey, Node Element)> Elements(Node definition)
    {
        foreach (var n in definition.Get("nodes").AsList())
        {
            if (n.Kind != NodeKind.Object) continue;
            var key = n.Get("key").AsString();
            foreach (var el in n.Get("elements").AsList())
                if (el.Kind == NodeKind.Object) yield return (key, el);
        }
    }

    // Every answerable slug (field and plugin elements) with its element and the key of its node.
    private static (Dictionary<string, Node> Elements, Dictionary<string, string?> NodeOf) AnswerElements(Node definition)
    {
        var elements = new Dictionary<string, Node>();
        var nodeOf = new Dictionary<string, string?>();
        foreach (var (nodeKey, el) in Elements(definition))
        {
            var kind = el.Get("kind").AsString();
            var slug = el.Get("slug").AsString();
            if (string.IsNullOrEmpty(slug) || (kind != "field" && kind != "plugin")) continue;
            elements[slug] = el;
            nodeOf[slug] = nodeKey;
        }
        return (elements, nodeOf);
    }

    /// <summary>
    /// The ONE live answer map inputs and bounds are read from: the stored answers the caller can
    /// read, overlaid with draft for the current step's slugs, plugin answers expanded, constants computed.
    /// </summary>
    internal static IReadOnlyDictionary<string, object?> LiveAnswers(
        FlowRun run, IReadOnlyDictionary<string, object?> stored, IReadOnlyDictionary<string, object?>? draft)
    {
        var merged = new Dictionary<string, object?>(stored);
        var (_, nodeOf) = AnswerElements(run.Definition);
        if (draft is not null && !string.IsNullOrEmpty(run.CurrentNode))
            foreach (var (k, v) in draft)
                if (nodeOf.TryGetValue(k, out var node) && node == run.CurrentNode) merged[k] = v;
        var constants = run.Definition.Get("constants").AsList();
        return FlowCondition.ComputeConstants(
            constants, FlowCondition.ExpandPluginAnswers(merged, PluginSlugsOf(run.Definition)), run.ReferenceDate);
    }

    // Decides whether a key of the live map reaches another party's private value, failing closed.
    private sealed class FlowPrivacy
    {
        private readonly FlowRun _run;
        private readonly IReadOnlyDictionary<string, object?>? _draft;
        private readonly string? _ownUser;
        private readonly HashSet<string>? _private;
        private readonly Dictionary<string, Node> _elements;
        private readonly Dictionary<string, string?> _nodeOf;
        private readonly Dictionary<string, Node> _constants = new();

        internal FlowPrivacy(FlowRun run, IReadOnlyDictionary<string, object?>? draft, string? ownUser)
        {
            _run = run;
            _draft = draft;
            _ownUser = ownUser;
            (_elements, _nodeOf) = AnswerElements(run.Definition);
            _private = run.PrivateSlugs is null ? null : new HashSet<string>(run.PrivateSlugs);
            foreach (var c in run.Definition.Get("constants").AsList())
                if (c.Get("key").AsString() is { Length: > 0 } k) _constants[k] = c;
        }

        // A slug in private_slugs (or, when the run carried no private_slugs, any slug another party
        // answers), a constant whose refs reach one, or a current-step draft whose field's default
        // reaches one.
        internal bool IsPrivate(string reference, HashSet<string> seen)
        {
            var dot = reference.IndexOf('.');
            var baseKey = dot >= 0 ? reference[..dot] : reference;
            if (!seen.Add(baseKey)) return false;
            if (_constants.TryGetValue(baseKey, out var constant))
                return ReachesPrivate(constant.Get("expr"), seen);
            if (_private is null)
            {
                if (_nodeOf.TryGetValue(baseKey, out var node)
                    && (_run.Bindings.TryGetValue(Client.PartyOf(_run.Definition, node) ?? "", out var uid) ? uid : null) != _ownUser)
                    return true;
            }
            else if (_private.Contains(baseKey))
            {
                return true;
            }
            if (_draft is not null && _draft.ContainsKey(baseKey)
                && _nodeOf.TryGetValue(baseKey, out var draftNode) && draftNode == _run.CurrentNode
                && _elements.TryGetValue(baseKey, out var el) && !el.Get("default").IsNull)
                return ReachesPrivate(el.Get("default"), seen);
            return false;
        }

        private bool ReachesPrivate(Node expr, HashSet<string> seen) =>
            FlowCondition.ExprRefs(expr).Any(r => IsPrivate(r, seen));
    }

    /// <summary>
    /// The submitted slugs whose answer is private by the same rule the plugin helpers apply to
    /// inputs: a field whose default reaches a private source. The submit carries
    /// <c>source_private: true</c> on exactly these.
    /// </summary>
    internal static HashSet<string> SourcePrivate(FlowRun run, IEnumerable<string> submitted, string? ownUser)
    {
        var slugs = submitted.Distinct().ToList();
        var draft = slugs.ToDictionary(s => s, s => (object?)true);
        var privacy = new FlowPrivacy(run, draft, ownUser);
        return slugs.Where(s => privacy.IsPrivate(s, new HashSet<string>())).ToHashSet();
    }

    // Resolve a plugin element's declared inputs from the live map, converted to their declared
    // types. A required input that cannot be sent throws PluginInputUnavailableException; an optional
    // one is left out of the call.
    private static Dictionary<string, object?> Inputs(Node spec, IReadOnlyDictionary<string, object?> live, FlowPrivacy privacy)
    {
        var wiring = spec.Get("inputs");
        var result = new Dictionary<string, object?>();
        foreach (var input in spec.Get("snapshot").Get("inputs").AsList())
        {
            if (input.Kind != NodeKind.Object) continue;
            var key = input.Get("key").AsString() ?? "";
            var required = ModelCoerce.CoerceBool(input.Get("required")) ?? false;
            string? reason = null;
            object? converted = null;
            var reference = wiring.Get(key).AsString();
            if (string.IsNullOrEmpty(reference))
                reason = PluginInputUnavailableException.Unwired;
            else if (!live.TryGetValue(reference, out var value) || value is null || value is string { Length: 0 })
                reason = PluginInputUnavailableException.Unanswered;
            else if (privacy.IsPrivate(reference, new HashSet<string>()))
                reason = PluginInputUnavailableException.OtherPartyPrivate;
            else if (!TryConvert(input.Get("type").AsString(), value, out converted))
                reason = PluginInputUnavailableException.NotConvertible;
            if (reason is null) result[key] = converted;
            else if (required)
                throw new PluginInputUnavailableException(key, string.IsNullOrEmpty(reference) ? null : reference, reason);
        }
        return result;
    }

    // number → a finite JSON number (through the evaluator's number coercion); date → a YYYY-MM-DD
    // string; boolean → a JSON boolean; text → a string.
    private static bool TryConvert(string? inputType, object value, out object? converted)
    {
        converted = null;
        switch (inputType)
        {
            case "number":
                var n = FlowCondition.NumberOf(value);
                if (n is null || !double.IsFinite(n.Value)) return false;
                converted = n.Value;
                return true;
            case "date":
                var d = FlowCondition.DateOf(value);
                if (d is null) return false;
                converted = d.Value.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
                return true;
            case "boolean":
                if (value is bool b) { converted = b; return true; }
                if (value is string s)
                {
                    if (s.Trim() == "true") { converted = true; return true; }
                    if (s.Trim() == "false") { converted = false; return true; }
                }
                return false;
            default:
                converted = FlowCondition.StringOf(value);
                return true;
        }
    }

    /// <summary>
    /// Check <paramref name="value"/> against the min and max of <paramref name="slug"/>'s field element,
    /// each evaluated over the live answer map; a bound that evaluates to null is no bound. Numbers
    /// compare as numbers and dates as dates. Throws <see cref="ValidationException"/> naming the bound.
    /// </summary>
    internal static void CheckBounds(FlowRun run, string slug, object? value, IReadOnlyDictionary<string, object?> live)
    {
        var element = Client.FieldElementForSlug(run.Definition, slug);
        if (element is null || value is null || value is string { Length: 0 }) return;
        foreach (var bound in new[] { "min", "max" })
        {
            var expr = element.Get(bound);
            if (expr.IsNull) continue;
            var limit = FlowCondition.EvalExpr(expr, live, run.ReferenceDate);
            if (limit is null) continue;
            var broken = false;
            var vn = FlowCondition.NumberOf(value);
            var ln = FlowCondition.NumberOf(limit);
            if (vn.HasValue && ln.HasValue)
            {
                broken = (bound == "min" && vn < ln) || (bound == "max" && vn > ln);
            }
            else if (FlowCondition.DateOf(value) is { } vd && FlowCondition.DateOf(limit) is { } ld)
            {
                broken = (bound == "min" && vd < ld) || (bound == "max" && vd > ld);
            }
            if (broken)
                throw new ValidationException(slug, Client.FieldTypeOfElement(element) ?? "", bound, limit);
        }
    }
}
